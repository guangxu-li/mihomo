package outbound_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
	_ "github.com/metacubex/mihomo/config" // sets dns.ParseNameServer
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type wgKeys struct{ private, public string }

func keys(t *testing.T) wgKeys {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return wgKeys{base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())}
}

func testPort(t *testing.T) int {
	t.Helper()
	// A fixed transport port is used on either loopback family.
	for i := 0; i < 50; i++ {
		v4 := listenTestUDP(t, net.IPv4(127, 0, 0, 1))
		port := v4.LocalAddr().(*net.UDPAddr).Port
		v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: port})
		_ = v4.Close()
		if v6 != nil {
			_ = v6.Close()
		}
		if !outbound.AddrInUse(err) {
			return port
		}
	}
	t.Fatal("no free transport port")
	return 0
}

func listenTestUDP(t *testing.T, ip net.IP) *net.UDPConn {
	t.Helper()
	// Keep allocation outside the ports used by common system services.
	for i := 0; i < 50; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10000))
		require.NoError(t, err)
		port := int(n.Int64()) + 36000
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: port})
		if outbound.AddrInUse(err) {
			continue
		}
		require.NoError(t, err)
		return c
	}
	t.Fatal("no free test port")
	return nil
}

type localTransport struct{ port int }

func (d localTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !ap.Addr().IsLoopback() {
		return nil, errors.New("expected loopback peer")
	}
	host := net.IPv4(127, 0, 0, 1)
	if ap.Addr().Is6() {
		host = net.IPv6loopback
	}
	return (&net.Dialer{LocalAddr: &net.UDPAddr{IP: host, Port: d.port}}).DialContext(ctx, network, address)
}
func (d localTransport) ListenPacket(ctx context.Context, network, address string, _ netip.AddrPort) (net.PacketConn, error) {
	if address == "" { // upstream multi-peer ClientBind requests an ephemeral socket
		address = net.JoinHostPort("", strconv.Itoa(d.port))
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	host := "127.0.0.1"
	if network == "udp6" {
		host = "::1"
	}
	return (&net.ListenConfig{}).ListenPacket(ctx, network, net.JoinHostPort(host, port))
}

// failingTransport cannot open a listening socket of one address family.
type failingTransport struct {
	localTransport
	network string
	err     error
}

func (d failingTransport) ListenPacket(ctx context.Context, network, address string, dst netip.AddrPort) (net.PacketConn, error) {
	if network == d.network {
		return nil, &net.OpError{Op: "listen", Net: network, Err: d.err}
	}
	return d.localTransport.ListenPacket(ctx, network, address, dst)
}

// As in wireguard-go, only an address family that the system lacks may be missing.
func TestWireGuardListenFamilies(t *testing.T) {
	for _, tt := range []struct {
		name    string
		network string
		err     error
		ok      bool
	}{
		{"no IPv6", "udp6", os.NewSyscallError("socket", syscall.EAFNOSUPPORT), true},
		{"no IPv4", "udp4", os.NewSyscallError("socket", syscall.EAFNOSUPPORT), true},
		{"IPv6 port occupied", "udp6", os.NewSyscallError("bind", syscall.EADDRINUSE), false},
		{"IPv6 refused", "udp6", os.NewSyscallError("bind", syscall.EACCES), false},
		{"IPv4 refused", "udp4", os.NewSyscallError("bind", syscall.EACCES), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			port := testPort(t)
			w := makeWG(t, outbound.WireGuardOption{BasicOption: outbound.BasicOption{DialerForAPI: failingTransport{network: tt.network, err: tt.err}},
				Name: "wg", Ip: "10.8.0.1", PrivateKey: keys(t).private, ListenPort: port,
				WireGuardPeerOption: outbound.WireGuardPeerOption{PublicKey: keys(t).public},
			})
			err := w.Start()
			if tt.ok {
				require.NoError(t, err)
				requirePeerField(t, w, fmt.Sprintf("listen_port=%d\n", port))
			} else {
				require.ErrorIs(t, err, tt.err)
				checkPort(t, port, false)
			}
		})
	}
}

type countedTransport struct {
	localTransport
	listens atomic.Int32
	dials   atomic.Int32
}

func (d *countedTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := d.localTransport.DialContext(ctx, network, address)
	if err == nil {
		d.dials.Add(1)
	}
	return c, err
}
func (d *countedTransport) ListenPacket(ctx context.Context, network, address string, dst netip.AddrPort) (net.PacketConn, error) {
	c, err := d.localTransport.ListenPacket(ctx, network, address, dst)
	if err == nil {
		d.listens.Add(1)
	}
	return c, err
}

func makeWG(t *testing.T, opts outbound.WireGuardOption) *outbound.WireGuard {
	t.Helper()
	opts.Workers = 1
	opts.UDP = true
	if opts.TunnelForAPI == nil {
		opts.TunnelForAPI = tunnel.Tunnel
	}
	if opts.DialerForAPI == nil {
		opts.DialerForAPI = localTransport{testPort(t)}
	}
	w, err := outbound.NewWireGuard(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func testRule(t *testing.T, tp, payload, target string) C.Rule {
	t.Helper()
	r, err := rules.ParseRule(tp, payload, target, nil, nil)
	require.NoError(t, err)
	return r
}

type testDNS struct{}

func (testDNS) ServeMsg(_ context.Context, q *D.Msg) (*D.Msg, error) {
	r := new(D.Msg)
	r.SetReply(q)
	r.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET}, A: net.IPv4(192, 0, 2, 1)}}
	return r, nil
}

func metadata(ip netip.Addr, port int) *C.Metadata {
	return &C.Metadata{DstIP: ip, DstPort: uint16(port)}
}
func dial(t *testing.T, w C.ProxyAdapter, ip netip.Addr, port int) C.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := w.DialContext(ctx, metadata(ip, port))
	require.NoError(t, err)
	require.NoError(t, c.SetDeadline(time.Now().Add(3*time.Second)))
	return c
}
func assertTCP(t *testing.T, c net.Conn) {
	t.Helper()
	require.NoError(t, c.SetDeadline(time.Now().Add(3*time.Second)))
	data := []byte("WireGuard TCP echo")
	_, err := c.Write(data)
	require.NoError(t, err)
	reply := make([]byte, len(data))
	_, err = io.ReadFull(c, reply)
	require.NoError(t, err)
	require.Equal(t, data, reply)
}

func assertUDP(t *testing.T, c net.PacketConn, ip netip.Addr, port int, data []byte) []byte {
	t.Helper()
	addr := netip.AddrPortFrom(ip, uint16(port))
	require.NoError(t, c.SetDeadline(time.Now().Add(3*time.Second)))
	_, err := c.WriteTo(data, net.UDPAddrFromAddrPort(addr))
	require.NoError(t, err)
	b := make([]byte, 1500)
	n, src, err := c.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, addr.String(), src.String())
	return b[:n]
}

func loopbackEcho(t *testing.T, ip netip.Addr) (int, int) {
	t.Helper()
	host := "127.0.0.1"
	if ip.Is6() {
		host = "::1"
	}
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	require.NoError(t, err)
	pc := listenTestUDP(t, net.ParseIP(host))
	t.Cleanup(func() { _ = l.Close(); _ = pc.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if c.RemoteAddr().(*net.TCPAddr).IP.String() == host {
					_, _ = io.Copy(c, c)
				}
			}(c)
		}
	}()
	go func() {
		b := make([]byte, 1500)
		for {
			n, src, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			if src.(*net.UDPAddr).IP.String() == host {
				_, _ = pc.WriteTo(b[:n], src)
			}
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, pc.LocalAddr().(*net.UDPAddr).Port
}

func checkTracked(t *testing.T, network C.NetWork, in string, src, dst netip.Addr, port, srcPort int, chain ...string) {
	t.Helper()
	found := false
	statistic.DefaultManager.Range(func(tr statistic.Tracker) bool {
		m := tr.Info().Metadata
		if m.Type == C.WIREGUARD && m.NetWork == network && m.InName == in && m.DstIP == dst && int(m.DstPort) == port && m.SrcIP == src && m.SrcPort != 0 && (srcPort == 0 || int(m.SrcPort) == srcPort) && slices.Equal(tr.Chains(), C.Chain(chain)) {
			found = true
		}
		return true
	})
	require.True(t, found, "missing %s tracker for %s -> %s:%d via %s", network, src, dst, port, chain)
}

func dnsQuery(t *testing.T) []byte {
	t.Helper()
	q := new(D.Msg)
	q.SetQuestion("example.test.", D.TypeA)
	b, err := q.Pack()
	require.NoError(t, err)
	return b
}
func dnsTCP(t *testing.T, c net.Conn, q []byte) []byte {
	t.Helper()
	head := make([]byte, 2)
	binary.BigEndian.PutUint16(head, uint16(len(q)))
	_, err := c.Write(append(head, q...))
	require.NoError(t, err)
	_, err = io.ReadFull(c, head)
	require.NoError(t, err)
	answer := make([]byte, binary.BigEndian.Uint16(head))
	_, err = io.ReadFull(c, answer)
	require.NoError(t, err)
	return answer
}
func checkDNS(t *testing.T, q, answer []byte) {
	t.Helper()
	m := new(D.Msg)
	require.NoError(t, m.Unpack(answer))
	require.Equal(t, binary.BigEndian.Uint16(q), m.Id)
	require.Len(t, m.Answer, 1)
	require.Equal(t, "192.0.2.1", m.Answer[0].(*D.A).A.String())
}

// A group can change its selection between rule matching and dialing.
type changingGroup struct {
	*outboundgroup.Selector
	other      C.Proxy
	selections atomic.Uint32
	otherDials atomic.Uint32
}

func (g *changingGroup) Unwrap(m *C.Metadata, touch bool) C.Proxy {
	if g.selections.Add(1)%2 == 0 {
		return g.Selector.Unwrap(m, touch)
	}
	if touch {
		g.otherDials.Add(1)
	}
	return g.other
}

func (g *changingGroup) DialContext(ctx context.Context, m *C.Metadata) (C.Conn, error) {
	return g.Unwrap(m, true).DialContext(ctx, m)
}

func (g *changingGroup) ListenPacketContext(ctx context.Context, m *C.Metadata) (C.PacketConn, error) {
	return g.Unwrap(m, true).ListenPacketContext(ctx, m)
}

func TestWireGuardInbound(t *testing.T) {
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(oldHome) })
	// REJECT's UDP socket returns EOF immediately. Hold that EOF until the
	// connections API has been inspected while preserving the real write path.
	release := make(chan struct{})
	defer close(release)
	reject := adapter.NewProxy(trackedReject{outbound.NewReject(), release})
	drop := adapter.NewProxy(trackedReject{outbound.NewRejectDrop(), release})
	pd, err := provider.NewCompatibleProvider("rejects", []C.Proxy{reject}, provider.NewHealthCheck(nil, "", 0, 0, true, nil))
	require.NoError(t, err)
	defer pd.Close()
	group, err := outboundgroup.NewSelector(outboundgroup.GroupCommonOption{Name: "RejectGroup"}, outboundgroup.SelectorOption{}, reject, []P.ProxyProvider{pd})
	require.NoError(t, err)
	someProxy := adapter.NewProxy(outbound.NewDnsWithOption(outbound.DnsOption{Name: "SomeProxy"}))
	changing := &changingGroup{Selector: group, other: someProxy}
	oldP, oldPV := tunnel.UpdateProxies(map[string]C.Proxy{
		"SomeProxy": someProxy,
		"REJECT":    reject, "REJECT-DROP": drop, "RejectGroup": adapter.NewProxy(changing), "DIRECT": adapter.NewProxy(outbound.NewDirect()),
	}, nil)
	oldR, oldSR, oldRP := tunnel.UpdateRules(nil, nil, nil)
	t.Cleanup(func() { tunnel.UpdateProxies(oldP, oldPV); tunnel.UpdateRules(oldR, oldSR, oldRP) })
	oldDNS := resolver.DefaultService.Load()
	resolver.DefaultService.Store(testDNS{})
	t.Cleanup(func() { resolver.DefaultService.Store(oldDNS) })
	tunnel.OnRunning()
	t.Run("multi-peer client bind", testMultiPeerClient)
	modes := []string{"mips"}
	if features.WithGVisor {
		modes = append(modes, "gvisor")
	}
	for _, version := range []int{1, 3} {
		t.Run(fmt.Sprintf("AmneziaWG-v%d", version), func(t *testing.T) { testAmnezia(t, version) })
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) { testInbound(t, mode) })
	}
	require.NotZero(t, changing.selections.Load())
	require.Zero(t, changing.otherDials.Load(), "a group dialed its next selection for an own-address flow")
}

type trackedReject struct {
	C.ProxyAdapter
	release <-chan struct{}
}

func (r trackedReject) ListenPacketContext(ctx context.Context, m *C.Metadata) (C.PacketConn, error) {
	pc, err := r.ProxyAdapter.ListenPacketContext(ctx, m)
	if err != nil {
		return nil, err
	}
	return heldRejectConn{pc, r.release}, nil
}

type heldRejectConn struct {
	C.PacketConn
	release <-chan struct{}
}

func (c heldRejectConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	<-c.release
	return c.PacketConn.WaitReadFrom()
}

// Only translate the final local service port so the host never binds port 53.
// The tunnel sees the original port for its rule match, tracker and DNS decision.
type testServicePort struct {
	C.ProxyAdapter
	port uint16
}

func (s testServicePort) DialContext(ctx context.Context, m *C.Metadata) (C.Conn, error) {
	dst := m.Clone()
	dst.DstPort = s.port
	return s.ProxyAdapter.DialContext(ctx, dst)
}
func (s testServicePort) ListenPacketContext(ctx context.Context, m *C.Metadata) (C.PacketConn, error) {
	pc, err := s.ProxyAdapter.ListenPacketContext(ctx, m)
	if err != nil {
		return nil, err
	}
	return testServicePacketConn{pc, s.port}, nil
}

type testServicePacketConn struct {
	C.PacketConn
	port uint16
}

func (c testServicePacketConn) WriteTo(p []byte, dst net.Addr) (int, error) {
	a := *dst.(*net.UDPAddr)
	a.Port = int(c.port)
	return c.PacketConn.WriteTo(p, &a)
}
func (c testServicePacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	data, put, src, err := c.PacketConn.WaitReadFrom()
	if err == nil {
		a := *src.(*net.UDPAddr)
		a.Port = 53
		src = &a
	}
	return data, put, src, err
}

type observedTunnel struct {
	C.Tunnel
	tcpService, udpService atomic.Uint32
	spoofed                atomic.Int32
}

func (o *observedTunnel) observe(m *C.Metadata, service uint32) {
	if m.SrcIP == netip.MustParseAddr("10.8.0.9") || m.SrcIP == netip.MustParseAddr("fd00:8::9") {
		o.spoofed.Add(1)
	}
	if m.DstPort == 53 && service != 0 && m.InboundLocal != nil && m.InboundLocal.Type() == C.WireGuard {
		m.InboundLocal = testServicePort{m.InboundLocal, uint16(service)}
	}
}
func (o *observedTunnel) HandleTCPConn(c net.Conn, m *C.Metadata) {
	o.observe(m, o.tcpService.Load())
	o.Tunnel.HandleTCPConn(c, m)
}
func (o *observedTunnel) HandleUDPPacket(p C.UDPPacket, m *C.Metadata) {
	o.observe(m, o.udpService.Load())
	o.Tunnel.HandleUDPPacket(p, m)
}

type countedWGDial struct {
	*outbound.WireGuard
	attempts int
	err      error
}

func (w *countedWGDial) DialContext(ctx context.Context, m *C.Metadata) (C.Conn, error) {
	w.attempts++
	conn, err := w.WireGuard.DialContext(ctx, m)
	w.err = err
	return conn, err
}
func checkTunnelFailFast(t *testing.T, w *outbound.WireGuard) {
	t.Helper()
	probe := &countedWGDial{WireGuard: w}
	old, pv := tunnel.UpdateProxies(map[string]C.Proxy{w.Name(): adapter.NewProxy(probe)}, nil)
	defer tunnel.UpdateProxies(old, pv)
	app, inbound := net.Pipe()
	defer app.Close()
	m := metadata(netip.MustParseAddr("10.8.0.2"), 12345)
	m.NetWork, m.Type, m.SpecialProxy = C.TCP, C.SOCKS5, w.Name()
	start := time.Now()
	tunnel.Tunnel.HandleTCPConn(inbound, m)
	require.Less(t, time.Since(start), time.Second)
	require.Equal(t, 1, probe.attempts)
	require.ErrorIs(t, probe.err, C.ErrNoWireGuardEndpoint)
}

func testMultiPeerClient(t *testing.T) {
	clientKey := keys(t)
	transport := &countedTransport{localTransport: localTransport{testPort(t)}}
	opts := outbound.WireGuardOption{BasicOption: outbound.BasicOption{DialerForAPI: transport}, Name: "wg-client", Ip: "10.8.0.2", PrivateKey: clientKey.private, AllowPeerAccess: true}
	for _, ip := range []string{"10.8.0.1", "10.8.0.3"} {
		node := keys(t)
		port := testPort(t)
		listener := makeWG(t, outbound.WireGuardOption{Name: "wg-" + ip, Ip: ip, PrivateKey: node.private, ListenPort: port,
			WireGuardPeerOption: outbound.WireGuardPeerOption{PublicKey: clientKey.public, AllowedIPs: []string{"10.8.0.2/32"}}})
		require.NoError(t, listener.Start())
		opts.Peers = append(opts.Peers, outbound.WireGuardPeerOption{PublicKey: node.public, Server: "127.0.0.1", Port: port, AllowedIPs: []string{ip + "/32"}})
	}
	client := makeWG(t, opts)
	require.NoError(t, client.Start())
	tunnel.UpdateRules([]C.Rule{testRule(t, "MATCH", "", "SomeProxy")}, nil, nil)
	for _, peer := range opts.Peers {
		dst := netip.MustParsePrefix(peer.AllowedIPs[0]).Addr()
		port, _ := loopbackEcho(t, dst)
		c := dial(t, client, dst, port)
		assertTCP(t, c)
		_ = c.Close()
	}
	require.EqualValues(t, 1, transport.listens.Load())
	require.Zero(t, transport.dials.Load())
}

func testAmnezia(t *testing.T, version int) {
	aKey, bKey := keys(t), keys(t)
	keepalive := 0
	if version == 1 {
		keepalive = 7
	}
	aPort, bPort := testPort(t), testPort(t)
	for aPort == bPort {
		bPort = testPort(t)
	}
	peer := func(name, ip string, src, dst int, private, public string) *outbound.WireGuard {
		return makeWG(t, outbound.WireGuardOption{
			BasicOption: outbound.BasicOption{DialerForAPI: localTransport{src}},
			Name:        name, Ip: ip, PrivateKey: private, AllowPeerAccess: true,
			AmneziaWGOption:     &outbound.AmneziaWGOption{Version: version, JC: 1, JMin: 8, JMax: 16, H1: "1234", H2: "2345", H3: "3456", H4: "4567"},
			WireGuardPeerOption: outbound.WireGuardPeerOption{PublicKey: public, Server: "127.0.0.1", Port: dst, Keepalive: keepalive},
		})
	}
	a := peer("wg-a", "10.8.0.1", aPort, bPort, aKey.private, bKey.public)
	b := peer("wg-b", "10.8.0.2", bPort, aPort, bKey.private, aKey.public)
	require.NoError(t, a.Start())
	require.NoError(t, b.Start())
	if version == 3 {
		// The v3 device omits a disabled keepalive from its UAPI response.
		require.False(t, strings.Contains(peerState(t, a), "persistent_keepalive_interval="))
	} else {
		requirePeerField(t, a, "persistent_keepalive_interval=7\n")
	}
	tunnel.UpdateRules([]C.Rule{testRule(t, "MATCH", "", "SomeProxy")}, nil, nil)
	ip := netip.MustParseAddr("10.8.0.1")
	port, _ := loopbackEcho(t, ip)
	// With a keepalive each peer sends a handshake as it starts, and the other
	// one may have no socket then. WireGuard waits 5 seconds before the next one.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := b.DialContext(ctx, metadata(ip, port))
	require.NoError(t, err)
	assertTCP(t, c)
	_ = c.Close()
}

func testInbound(t *testing.T, mode string) {
	serverKeys, clientKeys, otherKeys := keys(t), keys(t), keys(t)
	listenPort := testPort(t)
	configuredPort := testPort(t)
	for configuredPort == listenPort {
		configuredPort = testPort(t)
	}
	stack := outbound.IPStackOption{Mode: mode}
	observed := &observedTunnel{Tunnel: tunnel.Tunnel}
	listenerTransport := new(countedTransport)
	server := makeWG(t, outbound.WireGuardOption{BasicOption: outbound.BasicOption{TunnelForAPI: observed, DialerForAPI: listenerTransport}, Name: "wg-server", PrivateKey: serverKeys.private, Ip: "10.8.0.1", Ipv6: "fd00:8::1", IPStack: stack, ListenPort: listenPort,
		Peers: []outbound.WireGuardPeerOption{
			{PublicKey: clientKeys.public, AllowedIPs: []string{"10.8.0.2/32", "fd00:8::2/128"}},
			{PublicKey: otherKeys.public, AllowedIPs: []string{"10.8.0.4/32", "fd00:8::4/128"}, Server: "::ffff:127.0.0.1", Port: configuredPort, Keepalive: 0},
		}})
	require.NoError(t, server.Start())
	checkTunnelFailFast(t, server)
	key, err := base64.StdEncoding.DecodeString(clientKeys.public)
	require.NoError(t, err)
	_, block, ok := strings.Cut(peerState(t, server), "public_key="+hex.EncodeToString(key)+"\n")
	require.True(t, ok)
	block, _, _ = strings.Cut(block, "public_key=")
	require.True(t, strings.Contains(block, "persistent_keepalive_interval=0\n"), "passive peer should have no keepalive")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fast := time.Now()
	for _, address := range []string{"10.8.0.2", "::ffff:10.8.0.2", "fd00:8::2"} {
		dst := metadata(netip.MustParseAddr(address), 12345)
		_, err = server.DialContext(ctx, dst)
		require.ErrorIs(t, err, C.ErrNoWireGuardEndpoint)
		_, err = server.ListenPacketContext(ctx, dst)
		require.ErrorIs(t, err, C.ErrNoWireGuardEndpoint)
	}
	require.Less(t, time.Since(fast), time.Second)
	requirePeerField(t, server, fmt.Sprintf("listen_port=%d\n", listenPort))

	opts := outbound.WireGuardOption{Name: "wg-client", PrivateKey: clientKeys.private, Ip: "10.8.0.2", Ipv6: "fd00:8::2", IPStack: stack, AllowPeerAccess: true,
		WireGuardPeerOption: outbound.WireGuardPeerOption{PublicKey: serverKeys.public, Server: "127.0.0.1", Port: listenPort, AllowedIPs: []string{"10.8.0.0/24", "fd00:8::/64"}}}
	clientPort := testPort(t)
	for clientPort == configuredPort {
		clientPort = testPort(t)
	}
	clientTransport := &countedTransport{localTransport: localTransport{clientPort}}
	opts.DialerForAPI = clientTransport
	client := makeWG(t, opts)
	require.NoError(t, client.Start())
	requirePeerField(t, client, "persistent_keepalive_interval=25\n")
	tunnel.UpdateRules([]C.Rule{testRule(t, "MATCH", "", "SomeProxy")}, nil, nil)
	// A connected UDP peer accepts only datagrams sourced from listen-port.
	// With keepalive disabled the listening node must initiate the handshake.
	fixedOpts := opts
	fixedOpts.Name, fixedOpts.PrivateKey = "configured-peer", otherKeys.private
	fixedOpts.Ip, fixedOpts.Ipv6, fixedOpts.Keepalive = "10.8.0.4", "fd00:8::4", 0
	fixedTransport := &countedTransport{localTransport: localTransport{configuredPort}}
	fixedOpts.DialerForAPI = fixedTransport
	fixed := makeWG(t, fixedOpts)
	require.NoError(t, fixed.Start())
	require.Eventually(t, func() bool { return fixedTransport.dials.Load() == 1 }, time.Second, time.Millisecond)
	for _, address := range []string{fixedOpts.Ip, fixedOpts.Ipv6} {
		dst := netip.MustParseAddr(address)
		port, _ := loopbackEcho(t, dst)
		c := dial(t, server, dst, port)
		assertTCP(t, c)
		_ = c.Close()
	}
	require.EqualValues(t, 2, listenerTransport.listens.Load())
	require.Zero(t, listenerTransport.dials.Load())
	for _, family := range []struct{ own, peer, other string }{{"10.8.0.1", "10.8.0.2", "10.8.0.3"}, {"fd00:8::1", "fd00:8::2", "fd00:8::3"}} {
		t.Run(family.own, func(t *testing.T) {
			own, peer, other := netip.MustParseAddr(family.own), netip.MustParseAddr(family.peer), netip.MustParseAddr(family.other)
			tcpPort, udpPort := loopbackEcho(t, own)
			tunnel.UpdateRules([]C.Rule{testRule(t, "MATCH", "", "SomeProxy")}, nil, nil)
			c := dial(t, client, own, tcpPort)
			assertTCP(t, c)
			checkTracked(t, C.TCP, "wg-server", peer, own, tcpPort, c.LocalAddr().(*net.TCPAddr).Port, "wg-server")
			_ = c.Close()
			pc, err := client.ListenPacketContext(context.Background(), metadata(own, udpPort))
			require.NoError(t, err)
			defer pc.Close()
			data := []byte("WireGuard UDP echo")
			require.Equal(t, data, assertUDP(t, pc, own, udpPort, data))
			srcPort := pc.LocalAddr().(N.CustomAddr).RawAddr().(*net.UDPAddr).Port
			checkTracked(t, C.UDP, "wg-server", peer, own, udpPort, srcPort, "wg-server")

			// A single source port alternates between the host and a rule-selected relay.
			q := dnsQuery(t)
			checkDNS(t, q, assertUDP(t, pc, other, udpPort, q))
			checkTracked(t, C.UDP, "wg-server", peer, other, udpPort, srcPort, "SomeProxy")
			// Exit traffic from this source keeps its chosen relay across destinations.
			tunnel.UpdateRules([]C.Rule{testRule(t, "MATCH", "", "REJECT")}, nil, nil)
			checkDNS(t, q, assertUDP(t, pc, other, udpPort+1, q))
			tunnel.UpdateRules([]C.Rule{testRule(t, "MATCH", "", "SomeProxy")}, nil, nil)
			require.Equal(t, data, assertUDP(t, pc, own, udpPort, data))
			c = dial(t, client, other, tcpPort)
			checkDNS(t, q, dnsTCP(t, c, q))
			checkTracked(t, C.TCP, "wg-server", peer, other, tcpPort, c.LocalAddr().(*net.TCPAddr).Port, "SomeProxy")
			_ = c.Close()
			checkDNS(t, q, assertUDP(t, pc, own, 53, q))
			checkTracked(t, C.UDP, "wg-server", peer, own, 53, srcPort, "DNS")
			c = dial(t, client, own, 53)
			checkDNS(t, q, dnsTCP(t, c, q))
			checkTracked(t, C.TCP, "wg-server", peer, own, 53, 0, "DNS")
			_ = c.Close()

			// The disabled resolver must deliver to the local echo service.
			observed.tcpService.Store(uint32(tcpPort))
			observed.udpService.Store(uint32(udpPort))
			resolver.DefaultService.Store(nil)
			d := dial(t, client, own, 53)
			require.Equal(t, q, dnsTCP(t, d, q))
			checkTracked(t, C.TCP, "wg-server", peer, own, 53, d.LocalAddr().(*net.TCPAddr).Port, "wg-server")
			_ = d.Close()
			require.Equal(t, q, assertUDP(t, pc, own, 53, q))
			checkTracked(t, C.UDP, "wg-server", peer, own, 53, srcPort, "wg-server")
			resolver.DefaultService.Store(testDNS{})
			checkDNS(t, q, assertUDP(t, pc, own, 53, q))
			observed.tcpService.Store(0)
			observed.udpService.Store(0)

			// Reverse traffic uses the learned endpoint and the dialer's inbound.
			c = dial(t, server, peer, tcpPort)
			assertTCP(t, c)
			checkTracked(t, C.TCP, "wg-client", own, peer, tcpPort, c.LocalAddr().(*net.TCPAddr).Port, "wg-client")
			_ = c.Close()
			reverse, err := server.ListenPacketContext(context.Background(), metadata(peer, udpPort))
			require.NoError(t, err)
			require.Equal(t, data, assertUDP(t, reverse, peer, udpPort, data))
			_ = reverse.Close()
			c = dial(t, client, peer, tcpPort)
			assertTCP(t, c)
			_ = c.Close()
			testPing(t, client, peer, own)
			legacyOpt := opts
			legacyOpt.AllowPeerAccess = false
			legacy := makeWG(t, legacyOpt)
			lc := dial(t, legacy, peer, tcpPort)
			assertTCP(t, lc)
			_ = lc.Close()
			lp, err := legacy.ListenPacketContext(context.Background(), metadata(peer, udpPort))
			require.NoError(t, err)
			require.Equal(t, data, assertUDP(t, lp, peer, udpPort, data))
			_, err = lp.WriteTo(data, net.UDPAddrFromAddrPort(netip.AddrPortFrom(other, uint16(udpPort))))
			require.Error(t, err)
			_ = lp.Close()

			filter := fmt.Sprintf("((IN-TYPE,WIREGUARD),(IN-NAME,wg-server),(SRC-IP-CIDR,%s/%d),(IP-CIDR,%s/%d))", peer, peer.BitLen(), own, own.BitLen())
			tunnel.UpdateRules([]C.Rule{testRule(t, "AND", filter, "RejectGroup"), testRule(t, "MATCH", "", "SomeProxy")}, nil, nil)
			c = dial(t, client, own, tcpPort)
			_, _ = c.Write(data)
			b := make([]byte, 128)
			_, err = c.Read(b)
			require.Error(t, err)
			_ = c.Close()
			for _, choice := range []struct {
				rule  string
				chain []string
			}{
				{"REJECT", []string{"REJECT"}}, {"RejectGroup", []string{"REJECT"}}, {"REJECT-DROP", []string{"REJECT-DROP"}},
			} {
				// Only the echo port matches the rejection. The companion must pass.
				_, allowedPort := loopbackEcho(t, own)
				tunnel.UpdateRules([]C.Rule{testRule(t, "DST-PORT", strconv.Itoa(udpPort), choice.rule), testRule(t, "MATCH", "", "SomeProxy")}, nil, nil)
				fresh, err := client.ListenPacketContext(context.Background(), metadata(own, udpPort))
				require.NoError(t, err)
				require.Equal(t, data, assertUDP(t, fresh, own, allowedPort, data))
				source := fresh.LocalAddr().(N.CustomAddr).RawAddr().(*net.UDPAddr).Port
				checkTracked(t, C.UDP, "wg-server", peer, own, allowedPort, source, "wg-server")
				require.NoError(t, fresh.SetReadDeadline(time.Now().Add(180*time.Millisecond)))
				_, err = fresh.WriteTo(data, net.UDPAddrFromAddrPort(netip.AddrPortFrom(own, uint16(udpPort))))
				require.NoError(t, err)
				_, _, err = fresh.ReadFrom(b)
				require.Error(t, err)
				checkTracked(t, C.UDP, "wg-server", peer, own, udpPort, source, choice.chain...)
				_ = fresh.Close()
			}
		})
	}
	tunnel.UpdateRules([]C.Rule{testRule(t, "MATCH", "", "SomeProxy")}, nil, nil)
	own := netip.MustParseAddr("10.8.0.1")
	// Change the outer family and port while retaining the same authenticated key.
	require.NoError(t, client.Close())
	opts.Server = "::1"
	nextPort := testPort(t)
	opts.DialerForAPI = localTransport{nextPort}
	roaming := makeWG(t, opts)
	require.NoError(t, roaming.Start())
	tcpPort, _ := loopbackEcho(t, netip.MustParseAddr("10.8.0.1"))
	c := dial(t, roaming, netip.MustParseAddr("10.8.0.1"), tcpPort)
	assertTCP(t, c)
	_ = c.Close()
	requirePeerField(t, server, "endpoint=[::1]:"+strconv.Itoa(nextPort)+"\n")
	c = dial(t, server, netip.MustParseAddr("10.8.0.2"), tcpPort)
	assertTCP(t, c)
	_ = c.Close()
	require.NoError(t, roaming.Close())

	// The same authenticated key may reach these live services from its assigned IPs.
	servicePorts := make(map[netip.Addr]int)
	for _, address := range []string{"10.8.0.1", "fd00:8::1"} {
		dst := netip.MustParseAddr(address)
		_, port := loopbackEcho(t, dst)
		servicePorts[dst] = port
		valid, err := fixed.ListenPacketContext(context.Background(), metadata(dst, port))
		require.NoError(t, err)
		data := []byte("assigned source")
		require.Equal(t, data, assertUDP(t, valid, dst, port, data))
		_ = valid.Close()
	}
	require.NoError(t, fixed.Close())

	// The second peer authenticates independently on the same listening port.
	// Its assigned IPs below are deliberately outside this peer's allowed-ips.
	opts.PrivateKey = otherKeys.private
	opts.Ip, opts.Ipv6 = "10.8.0.9", "fd00:8::9"
	spoofTransport := &countedTransport{localTransport: localTransport{testPort(t)}}
	opts.DialerForAPI = spoofTransport
	spoof := makeWG(t, opts)
	require.NoError(t, spoof.Start())
	require.Eventually(t, func() bool { return spoofTransport.dials.Load() == 1 }, time.Second, time.Millisecond)
	endpoint := "endpoint=[::1]:" + strconv.Itoa(spoofTransport.port) + "\n"
	require.Eventually(t, func() bool { return strings.Contains(peerState(t, server), endpoint) }, 7*time.Second, 10*time.Millisecond)
	for own, port := range servicePorts {
		pc, err := spoof.ListenPacketContext(context.Background(), metadata(own, port))
		require.NoError(t, err)
		require.NoError(t, pc.SetReadDeadline(time.Now().Add(180*time.Millisecond)))
		_, err = pc.WriteTo([]byte("unassigned source"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(own, uint16(port))))
		require.NoError(t, err)
		_, _, err = pc.ReadFrom(make([]byte, 128))
		require.Error(t, err)
		_ = pc.Close()
	}
	require.Zero(t, observed.spoofed.Load())

	// Establish an outbound-only client, then open a new flow back toward it.
	opts.PrivateKey, opts.Ip, opts.Ipv6 = clientKeys.private, "10.8.0.2", "fd00:8::2"
	opts.AllowPeerAccess = false
	opts.DialerForAPI = localTransport{testPort(t)}
	outboundOnly := makeWG(t, opts)
	forward := dial(t, outboundOnly, own, tcpPort)
	assertTCP(t, forward)
	_ = forward.Close()
	peer := netip.MustParseAddr("10.8.0.2")
	testPing(t, outboundOnly, peer, own)
	testPing(t, server, own, peer)
	testPing(t, server, netip.MustParseAddr("fd00:8::1"), netip.MustParseAddr("fd00:8::2"))
	rejectCtx, cancelReject := context.WithTimeout(context.Background(), 400*time.Millisecond)
	denied, err := server.DialContext(rejectCtx, metadata(peer, tcpPort))
	cancelReject()
	if denied != nil {
		_ = denied.Close()
	}
	require.Error(t, err)
	_, udpPort := loopbackEcho(t, own)
	deniedUDP, err := server.ListenPacketContext(context.Background(), metadata(peer, udpPort))
	require.NoError(t, err)
	_ = deniedUDP.SetReadDeadline(time.Now().Add(180 * time.Millisecond))
	_, err = deniedUDP.WriteTo([]byte("outbound only"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(peer, uint16(udpPort))))
	require.NoError(t, err)
	_, _, err = deniedUDP.ReadFrom(make([]byte, 128))
	require.Error(t, err)
	_ = deniedUDP.Close()
}

func requirePeerField(t *testing.T, w *outbound.WireGuard, field string) {
	t.Helper()
	require.True(t, strings.Contains(peerState(t, w), field), "missing peer field %q", field)
}

func peerState(t *testing.T, w *outbound.WireGuard) string {
	t.Helper()
	s, err := w.TestPeerState()
	require.NoError(t, err)
	return s
}

func testPing(t *testing.T, w *outbound.WireGuard, src, dst netip.Addr) {
	t.Helper()
	c, err := w.TestDialIP(src, dst)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SetDeadline(time.Now().Add(2*time.Second)))
	payload := []byte("WireGuard ping")
	echo := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 7, Seq: 1, Data: payload}}
	var pseudo []byte
	header := make([]byte, 20)
	header[0], header[8], header[9] = 0x45, 64, 1
	copy(header[12:16], src.AsSlice())
	copy(header[16:20], dst.AsSlice())
	replyType := byte(0)
	if src.Is6() {
		echo.Type = ipv6.ICMPTypeEchoRequest
		pseudo = icmp.IPv6PseudoHeader(src.AsSlice(), dst.AsSlice())
		header = make([]byte, 40)
		header[0], header[6], header[7] = 0x60, 58, 64
		copy(header[8:24], src.AsSlice())
		copy(header[24:40], dst.AsSlice())
		replyType = 129
	}
	body, err := echo.Marshal(pseudo)
	require.NoError(t, err)
	if src.Is4() {
		binary.BigEndian.PutUint16(header[2:], uint16(len(header)+len(body)))
		var sum uint32
		for i := 0; i < len(header); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(header[i:]))
		}
		for sum > 65535 {
			sum = (sum & 65535) + (sum >> 16)
		}
		binary.BigEndian.PutUint16(header[10:], ^uint16(sum))
	} else {
		binary.BigEndian.PutUint16(header[4:], uint16(len(body)))
	}
	_, err = c.Write(append(header, body...))
	require.NoError(t, err)
	b := make([]byte, 1500)
	n, err := c.Read(b)
	require.NoError(t, err)
	require.Greater(t, n, len(header))
	require.Equal(t, replyType, b[len(header)])
	require.True(t, bytes.HasSuffix(b[:n], payload))
}

func TestWireGuardValidation(t *testing.T) {
	k, peer := keys(t), keys(t)
	for _, tt := range []struct {
		name string
		opts map[string]any
		want string
	}{
		{"missing endpoint", map[string]any{"allow-peer-access": true}, "listen-port"},
		{"half endpoint", map[string]any{"server": "127.0.0.1", "listen-port": 51900}, "requires a server"},
		{"empty peer endpoint", map[string]any{"allow-peer-access": true, "peers": []any{map[string]any{"public-key": peer.public, "allowed-ips": []any{"10.8.0.2/32"}}}}, "listen-port"},
		{"duplicate", map[string]any{"listen-port": 51900, "peers": []any{map[string]any{"public-key": peer.public, "allowed-ips": []any{"10.8.0.2/32"}}, map[string]any{"public-key": peer.public, "allowed-ips": []any{"10.8.0.3/32"}}}}, "same public-key"},
		{"zero", map[string]any{"listen-port": 0, "accept-incoming": true}, "listen-port"},
		{"null with no endpoint", map[string]any{"listen_port": nil, "accept-incoming": true}, "listen-port"},
		{"scientific notation", map[string]any{"listen-port": "1e4"}, "listen-port"},
		{"decimal string", map[string]any{"listen-port": "51900.0"}, "listen-port"},
		{"JSON number", map[string]any{"listen-port": float64(51900)}, ""},
		{"negative", map[string]any{"listen-port": -1}, "listen-port"},
		{"overflow", map[string]any{"listen-port": 65536}, "listen-port"},
		{"alias", map[string]any{"server": "127.0.0.1", "port": 51900, "accept-incoming": true}, ""},
		{"top level passive", map[string]any{"listen-port": 51900}, ""},
		{"ip-stack", map[string]any{"listen-port": 51900, "ip-stack": map[string]any{"mode": "mips"}}, ""},
		{"amnezia listening", map[string]any{"listen-port": 51900, "amnezia-wg-option": map[string]any{"jc": 2}}, "amnezia-wg-option"},
		{"reserved listening", map[string]any{"listen-port": 51900, "reserved": []any{1, 2, 3}}, "reserved"},
		{"allowed-ips", map[string]any{"listen-port": 51900, "allowed-ips": []any{"10.8.0.2"}}, "allowed-ips"},
		{"short public-key", map[string]any{"listen-port": 51900, "public-key": "c2hvcnQ="}, "32 bytes"},
		{"missing public-key", map[string]any{"listen-port": 51900, "public-key": ""}, "32 bytes"},
		{"peer keepalive", map[string]any{"listen-port": 51900, "peers": []any{map[string]any{"public-key": peer.public, "allowed-ips": []any{"10.8.0.2/32"}, "persistent-keepalive": "auto"}}}, "persistent-keepalive"},
		{"peer keepalive as text", map[string]any{"listen-port": 51900, "peers": []any{map[string]any{"public-key": peer.public, "allowed-ips": []any{"10.8.0.2/32"}, "persistent-keepalive": "15"}}}, ""},
		{"peer keepalive range", map[string]any{"listen-port": 51900, "peers": []any{map[string]any{"public-key": peer.public, "allowed-ips": []any{"10.8.0.2/32"}, "persistent-keepalive": 65536}}}, "between 0 and 65535"},
		{"keepalive range", map[string]any{"listen-port": 51900, "persistent-keepalive": 65536}, "between 0 and 65535"},
		{"shared endpoint", map[string]any{"allow-peer-access": true, "peers": []any{map[string]any{"server": "wg.invalid", "port": 51900, "public-key": peer.public, "allowed-ips": []any{"10.8.0.2/32"}}, map[string]any{"server": "wg.invalid", "port": 51900, "public-key": k.public, "allowed-ips": []any{"10.8.0.3/32"}}}}, "same server and port"},
		{"shared server", map[string]any{"allow-peer-access": true, "peers": []any{map[string]any{"server": "wg.invalid", "port": 51900, "public-key": peer.public, "allowed-ips": []any{"10.8.0.2/32"}}, map[string]any{"server": "wg.invalid", "port": 51901, "public-key": k.public, "allowed-ips": []any{"10.8.0.3/32"}}}}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := map[string]any{"name": "wg", "type": "wireguard", "ip": "10.8.0.1", "private-key": k.private, "public-key": peer.public}
			for k, v := range tt.opts {
				m[k] = v
			}
			p, err := adapter.ParseProxy(m, adapter.WithTunnelForAPI(tunnel.Tunnel))
			if tt.want != "" {
				require.ErrorContains(t, err, tt.want)
				return
			}
			require.NoError(t, err)
			require.True(t, outbound.HasWireGuardPeerAccess(p))
			_ = p.Close()
		})
	}
	// A proxy without the new options is checked as before.
	for name, opts := range map[string]map[string]any{
		"missing endpoint":   nil,
		"listen-port unset":  {"listen-port": 0},
		"endpoint port":      {"server": "127.0.0.1", "port": 65536},
		"repeated peer keys": {"peers": []any{map[string]any{"server": "127.0.0.1", "port": 51900, "public-key": peer.public, "allowed-ips": []any{"10.8.0.2/32"}}, map[string]any{"server": "127.0.0.1", "port": 51901, "public-key": peer.public, "allowed-ips": []any{"10.8.0.3/32"}}}},
		"peer keepalive":     {"peers": []any{map[string]any{"server": "127.0.0.1", "port": 51900, "public-key": peer.public, "allowed-ips": []any{"10.8.0.2/32"}, "persistent-keepalive": "auto"}}},
		"short public-key":   {"server": "127.0.0.1", "port": 51900, "public-key": "c2hvcnQ="},
		"keepalive range":    {"server": "127.0.0.1", "port": 51900, "persistent-keepalive": 65536},
		"shared endpoint":    {"peers": []any{map[string]any{"server": "127.0.0.1", "port": 51900, "public-key": peer.public, "allowed-ips": []any{"10.8.0.2/32"}}, map[string]any{"server": "127.0.0.1", "port": 51900, "public-key": k.public, "allowed-ips": []any{"10.8.0.3/32"}}}},
	} {
		t.Run("legacy "+name, func(t *testing.T) {
			m := map[string]any{"name": "wg", "type": "wireguard", "ip": "10.8.0.1", "private-key": k.private, "public-key": peer.public}
			for k, v := range opts {
				m[k] = v
			}
			p, err := adapter.ParseProxy(m, adapter.WithTunnelForAPI(tunnel.Tunnel))
			require.NoError(t, err)
			require.False(t, outbound.HasWireGuardPeerAccess(p))
		})
	}
	if !features.WithGVisor {
		_, err := outbound.NewWireGuard(outbound.WireGuardOption{PrivateKey: k.private, Ip: "10.8.0.1", IPStack: outbound.IPStackOption{Mode: "gvisor"}, WireGuardPeerOption: outbound.WireGuardPeerOption{Server: "127.0.0.1", Port: 51900, PublicKey: peer.public}})
		require.ErrorContains(t, err, "with_gvisor")
	}
}

func TestWireGuardListeningDialerProxy(t *testing.T) {
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	opts := listenerOptions(t, testPort(t))
	opts["dialer-proxy"] = "unused"
	p := parseListener(t, opts)
	defer p.Close()
	require.Empty(t, p.ProxyInfo().DialerProxy)
	const marker = "WireGuard listener parse complete"
	log.Debugln(marker)
	count := 0
	timeout := time.After(time.Second)
	for {
		select {
		case event := <-sub:
			if event.LogLevel == log.WARNING && strings.Contains(event.Payload, "ignoring dialer-proxy with listen-port") {
				count++
			}
			if event.Payload == marker {
				require.Equal(t, 1, count)
				return
			}
		case <-timeout:
			t.Fatal("missing parse completion event")
		}
	}
}

// The proxy's own IPv6 address is local, whatever resolves names for the tunnel.
func TestWireGuardOwnAddressWithRemoteDNS(t *testing.T) {
	prev := resolver.DisableIPv6
	resolver.DisableIPv6 = true // the global ipv6 option is off
	t.Cleanup(func() { resolver.DisableIPv6 = prev })
	w := makeWG(t, outbound.WireGuardOption{Name: "wg", Ip: "10.8.0.1", Ipv6: "fd00:8::1", PrivateKey: keys(t).private,
		RemoteDnsResolve: true, Dns: []string{"10.8.0.53"},
		WireGuardPeerOption: outbound.WireGuardPeerOption{PublicKey: keys(t).public, Server: "127.0.0.1", Port: testPort(t)}})
	for _, own := range []netip.Addr{netip.MustParseAddr("10.8.0.1"), netip.MustParseAddr("fd00:8::1")} {
		tcp, udp := loopbackEcho(t, own)
		c := dial(t, w, own, tcp)
		assertTCP(t, c)
		_ = c.Close()
		pc, err := w.ListenPacketContext(context.Background(), metadata(own, udp))
		require.NoError(t, err)
		assertUDP(t, pc, own, udp, []byte("WireGuard UDP echo"))
		_ = pc.Close()
	}
}
