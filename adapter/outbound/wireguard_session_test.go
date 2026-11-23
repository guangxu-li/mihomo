package outbound_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/sing/common/control"
	"github.com/stretchr/testify/require"
)

func listenerOptions(t *testing.T, port int) map[string]any {
	t.Helper()
	return map[string]any{"name": "wg", "type": "wireguard", "listen-port": port, "ip": "10.8.0.1", "ipv6": "fd00:8::1", "private-key": keys(t).private, "public-key": keys(t).public, "workers": 1, "allowed-ips": []string{"10.8.0.2/32", "fd00:8::2/128"}}
}

func parseListener(t *testing.T, m map[string]any) C.Proxy {
	t.Helper()
	p, err := adapter.ParseProxy(m, adapter.WithTunnelForAPI(tunnel.Tunnel), adapter.WithDialerForAPI(localTransport{}))
	require.NoError(t, err)
	return p
}

// syncWG runs the sessions of proxies the way the executor does for a config.
func syncWG(t *testing.T, proxies ...C.Proxy) {
	t.Helper()
	outbound.OpenWireGuard(nil) // an earlier test may have closed the sessions, or left its callback
	outbound.SyncWireGuard(proxies, true)
	t.Cleanup(func() { outbound.SyncWireGuard(nil, true) })
}

// session returns the running session that p uses.
func session(t *testing.T, p C.Proxy) *outbound.WireGuard {
	t.Helper()
	s, err := outbound.WireGuardSession(p)
	require.NoError(t, err, "%s has no running session", p.Name())
	return s
}

// checkPort tells whether a socket holds the port, for each address family.
func checkPort(t *testing.T, port int, busy bool) {
	t.Helper()
	bind := func(network string, ip net.IP) error {
		pc, err := net.ListenUDP(network, &net.UDPAddr{IP: ip, Port: port})
		if pc != nil {
			_ = pc.Close()
		}
		return err
	}
	for _, family := range []struct {
		network  string
		loopback net.IP
	}{{"udp4", net.IPv4(127, 0, 0, 1)}, {"udp6", net.IPv6loopback}} {
		err := bind(family.network, family.loopback)
		if err == nil && runtime.GOOS == "windows" {
			// Windows lets a loopback socket share the port of a wildcard socket.
			err = bind(family.network, nil)
		}
		if busy {
			require.Error(t, err, "port %d should be held on %s", port, family.loopback)
		} else {
			require.NoError(t, err)
		}
	}
}

func checkStopped(t *testing.T, done <-chan struct{}) {
	t.Helper()
	require.NotNil(t, done)
	select {
	case <-done:
	default:
		t.Fatal("WireGuard device still running")
	}
}

// Exercise net.ListenConfig and the real WireGuard bind, restricted to loopback.
// On Windows the sockets are not restricted: binding to an interface there
// only chooses where a socket sends from.
func withLoopbackSockets(t *testing.T, onBind func() error) {
	t.Helper()
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, it := range interfaces {
		if it.Flags&net.FlagLoopback == 0 {
			continue
		}
		lo := it
		prev := dialer.DefaultSocketHook
		dialer.DefaultSocketHook = func(network, address string, raw syscall.RawConn) error {
			if onBind != nil {
				if err := onBind(); err != nil {
					return err
				}
			}
			if runtime.GOOS == "windows" {
				return nil
			}
			return control.BindToInterface0(nil, raw, network, "", lo.Name, lo.Index, true)
		}
		t.Cleanup(func() { dialer.DefaultSocketHook = prev })
		return
	}
	t.Fatal("missing loopback interface")
}

// testLookup resolves every name to loopback, or fails while fail is set. A
// name that starts with "slow" waits for hold when that is set, and one that
// starts with "missing" always fails. Any other name takes delay.
type testLookup struct {
	resolver.Resolver
	fail    atomic.Bool
	lookups atomic.Int32
	hold    chan struct{}
	held    chan struct{} // gets a value when a lookup waits
	delay   time.Duration
}

func (r *testLookup) Invalid() bool { return true }

func (r *testLookup) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	r.lookups.Add(1)
	if r.fail.Load() || strings.HasPrefix(host, "missing") {
		return nil, errors.New("test lookup failure")
	}
	if r.hold != nil && strings.HasPrefix(host, "slow") {
		select {
		case r.held <- struct{}{}:
		default:
		}
		select {
		case <-r.hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	} else if r.delay != 0 {
		select {
		case <-time.After(r.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func (r *testLookup) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}

func withLookup(t *testing.T) *testLookup {
	t.Helper()
	lookup := &testLookup{}
	prev := resolver.ProxyServerHostResolver
	resolver.ProxyServerHostResolver = lookup
	t.Cleanup(func() { resolver.ProxyServerHostResolver = prev })
	return lookup
}

func TestWireGuardConflictingListeners(t *testing.T) {
	var binds atomic.Int32
	withLoopbackSockets(t, func() error { binds.Add(1); return nil })
	port := testPort(t)
	owner, peer := keys(t), keys(t)
	m := listenerOptions(t, port)
	m["private-key"], m["public-key"] = owner.private, peer.public
	parse := func(name string) C.Proxy {
		m["name"] = name
		p, err := adapter.ParseProxy(m, adapter.WithTunnelForAPI(tunnel.Tunnel))
		require.NoError(t, err)
		return p
	}
	first, same, second := parse("first"), parse("first"), parse("second")
	own := netip.MustParseAddr("10.8.0.1")
	remote := netip.MustParseAddr("10.8.0.2")
	echo, _ := loopbackEcho(t, own)
	for _, dst := range []netip.Addr{own, remote} {
		_, err := second.DialContext(context.Background(), metadata(dst, echo))
		require.ErrorContains(t, err, "not running")
		_, err = second.ListenPacketContext(context.Background(), metadata(dst, echo))
		require.ErrorContains(t, err, "not running")
	}
	checkPort(t, port, false)

	syncWG(t, first, same)
	require.EqualValues(t, 2, binds.Load(), "one socket per family for both proxies")
	require.Same(t, session(t, first), session(t, same))
	client := func() *outbound.WireGuard {
		return makeWG(t, outbound.WireGuardOption{Name: "client", Ip: "10.8.0.2", PrivateKey: peer.private,
			WireGuardPeerOption: outbound.WireGuardPeerOption{PublicKey: owner.public, Server: "127.0.0.1", Port: port}})
	}
	c := dial(t, client(), own, echo)
	defer c.Close()
	assertTCP(t, c)
	done := session(t, first).TestDeviceDone()

	// A second proxy on the same port does not disturb the first one.
	syncWG(t, first, same, second)
	_, err := second.DialContext(context.Background(), metadata(remote, echo))
	require.True(t, outbound.AddrInUse(err), err)
	require.ErrorContains(t, err, first.Name())
	_, err = second.ListenPacketContext(context.Background(), metadata(remote, echo))
	require.True(t, outbound.AddrInUse(err), err)
	assertTCP(t, c)

	// It takes the port over in the sync that drops the first one.
	syncWG(t, second)
	checkStopped(t, done)
	checkPort(t, port, true)
	_, err = second.ListenPacketContext(context.Background(), metadata(remote, echo))
	require.ErrorIs(t, err, C.ErrNoWireGuardEndpoint)
	_, err = first.DialContext(context.Background(), metadata(own, echo))
	require.ErrorContains(t, err, "not running")
	fresh := dial(t, client(), own, echo)
	defer fresh.Close()
	assertTCP(t, fresh)

	done = session(t, second).TestDeviceDone()
	syncWG(t)
	checkStopped(t, done)
	checkPort(t, port, false)
}

// A session that cannot start asks for another sync, and starts in it.
func TestWireGuardStartRetry(t *testing.T) {
	lookup := withLookup(t)
	lookup.fail.Store(true)
	m := listenerOptions(t, testPort(t))
	delete(m, "listen-port")
	m["server"], m["port"], m["allow-peer-access"] = "wg-endpoint.invalid", testPort(t), true
	p := parseListener(t, m)
	refresh := make(chan struct{}, 1)
	outbound.OpenWireGuard(func() {
		select {
		case refresh <- struct{}{}:
		default:
		}
	})
	resync := func() { outbound.SyncWireGuard([]C.Proxy{p}, true) }
	t.Cleanup(func() { outbound.OpenWireGuard(nil); outbound.SyncWireGuard(nil, true) })

	resync()
	_, err := p.DialContext(context.Background(), metadata(netip.MustParseAddr("10.8.0.2"), 9))
	require.ErrorContains(t, err, "not running")
	require.ErrorContains(t, err, "test lookup failure")
	select {
	case <-refresh:
	case <-time.After(3 * time.Second):
		t.Fatal("no retry was asked for")
	}
	lookup.fail.Store(false)
	resync()
	done := session(t, p).TestDeviceDone()
	select {
	case <-refresh:
		t.Fatal("a running session asked for a retry")
	case <-time.After(1500 * time.Millisecond):
	}
	outbound.SyncWireGuard(nil, true)
	checkStopped(t, done)
}

// A listening proxy serves its other peers while one endpoint does not resolve.
func TestWireGuardListenerWithoutEndpoint(t *testing.T) {
	lookup := withLookup(t)
	lookup.fail.Store(true)
	port, sibling := testPort(t), testPort(t)
	node, passive := keys(t), keys(t)
	m := listenerOptions(t, port)
	delete(m, "public-key")
	delete(m, "allowed-ips")
	m["private-key"] = node.private
	m["peers"] = []map[string]any{
		{"public-key": passive.public, "allowed-ips": []string{"10.8.0.2/32"}},
		{"public-key": keys(t).public, "allowed-ips": []string{"10.8.0.3/32"}, "server": "wg-endpoint.invalid", "port": sibling},
	}
	p := parseListener(t, m)
	refresh := make(chan struct{}, 1)
	outbound.OpenWireGuard(func() {
		select {
		case refresh <- struct{}{}:
		default:
		}
	})
	resync := func() { outbound.SyncWireGuard([]C.Proxy{p}, true) }
	t.Cleanup(func() { outbound.OpenWireGuard(nil); outbound.SyncWireGuard(nil, true) })

	resync()
	require.EqualValues(t, 1, lookup.lookups.Load(), "one lookup for one start")
	checkPort(t, port, true)
	running := session(t, p)
	own := netip.MustParseAddr("10.8.0.1")
	echo, _ := loopbackEcho(t, own)
	client := makeWG(t, outbound.WireGuardOption{Name: "client", Ip: "10.8.0.2", PrivateKey: passive.private,
		WireGuardPeerOption: outbound.WireGuardPeerOption{PublicKey: node.public, Server: "127.0.0.1", Port: port}})
	c := dial(t, client, own, echo)
	defer c.Close()
	assertTCP(t, c)
	_, err := p.DialContext(context.Background(), metadata(netip.MustParseAddr("10.8.0.3"), 9))
	require.ErrorIs(t, err, C.ErrNoWireGuardEndpoint)
	require.NotContains(t, peerState(t, running), fmt.Sprintf("endpoint=127.0.0.1:%d\n", sibling))
	select {
	case <-refresh:
	case <-time.After(3 * time.Second):
		t.Fatal("no retry was asked for")
	}

	// A lookup that fails again changes nothing.
	resync()
	require.Same(t, running, session(t, p))
	assertTCP(t, c)

	// Once the name resolves, the device gets the endpoint and starts the handshake.
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sibling})
	require.NoError(t, err)
	defer remote.Close()
	lookup.fail.Store(false)
	resync()
	require.Same(t, running, session(t, p))
	requirePeerField(t, running, fmt.Sprintf("endpoint=127.0.0.1:%d\n", sibling))
	requirePeerField(t, running, "persistent_keepalive_interval=25\n")
	require.NoError(t, remote.SetReadDeadline(time.Now().Add(3*time.Second)))
	n, _, err := remote.ReadFrom(make([]byte, 256))
	require.NoError(t, err)
	require.Equal(t, 148, n, "a handshake initiation")
	assertTCP(t, c)
	select {
	case <-refresh:
		t.Fatal("a complete session asked for a retry")
	case <-time.After(1500 * time.Millisecond):
	}
}

// A listening proxy listens however long the lookup of an endpoint name takes,
// and the names that do not answer leave time for one that answers late.
func TestWireGuardListenerSlowLookup(t *testing.T) {
	lookup := withLookup(t)
	lookup.hold, lookup.held, lookup.delay = make(chan struct{}), make(chan struct{}, 1), 400*time.Millisecond
	port, sibling := testPort(t), testPort(t)
	m := listenerOptions(t, port)
	delete(m, "public-key")
	delete(m, "allowed-ips")
	peers := []map[string]any{{"public-key": keys(t).public, "allowed-ips": []string{"10.8.0.2/32"}}}
	for i := 0; i < 7; i++ {
		peers = append(peers, map[string]any{"public-key": keys(t).public, "allowed-ips": []string{fmt.Sprintf("10.8.0.%d/32", 10+i)}, "server": fmt.Sprintf("slow-%d.invalid", i), "port": sibling})
	}
	m["peers"] = append(peers, map[string]any{"public-key": keys(t).public, "allowed-ips": []string{"10.8.0.3/32"}, "server": "wg-endpoint.invalid", "port": sibling})
	p := parseListener(t, m)
	started, synced := time.Now(), make(chan struct{})
	go func() { syncWG(t, p); close(synced) }()
	waitFor(t, lookup.held)
	checkPort(t, port, true)
	select {
	case <-synced:
	case <-time.After(C.DefaultTCPTimeout):
		t.Fatal("the names do not share the time of one start")
	}
	require.Less(t, time.Since(started), C.DefaultTCPTimeout)
	require.Equal(t, 1, strings.Count(peerState(t, session(t, p)), fmt.Sprintf("endpoint=127.0.0.1:%d\n", sibling)), "the name after the slow ones")
}

// A sync looks up only the names that have no address yet.
func TestWireGuardListenerPendingLookups(t *testing.T) {
	lookup := withLookup(t)
	sibling := testPort(t)
	m := listenerOptions(t, testPort(t))
	delete(m, "public-key")
	delete(m, "allowed-ips")
	m["peers"] = []map[string]any{
		{"public-key": keys(t).public, "allowed-ips": []string{"10.8.0.2/32"}, "server": "wg-endpoint.invalid", "port": sibling},
		{"public-key": keys(t).public, "allowed-ips": []string{"10.8.0.3/32"}, "server": "missing.invalid", "port": sibling},
	}
	p := parseListener(t, m)
	syncWG(t, p)
	require.EqualValues(t, 2, lookup.lookups.Load())
	require.Equal(t, 1, strings.Count(peerState(t, session(t, p)), "\nendpoint="))
	syncWG(t, p)
	require.EqualValues(t, 3, lookup.lookups.Load(), "the name that has its address is not looked up again")
}

// A session that dials waits for its transport no longer than its start may
// take, and a CloseWireGuard ends that wait: a dialer-proxy may take long to
// connect.
func TestWireGuardDialerStartsLater(t *testing.T) {
	hold, entered := make(chan struct{}), make(chan struct{}, 4)
	m := listenerOptions(t, testPort(t))
	delete(m, "listen-port")
	m["allow-peer-access"], m["server"], m["port"] = true, "127.0.0.1", testPort(t)
	p, err := adapter.ParseProxy(m, adapter.WithTunnelForAPI(tunnel.Tunnel), adapter.WithDialerForAPI(heldTransport{hold: hold, entered: entered}))
	require.NoError(t, err)
	outbound.OpenWireGuard(nil)
	t.Cleanup(func() { outbound.OpenWireGuard(nil); outbound.SyncWireGuard(nil, true) })
	t.Cleanup(func() { close(hold) }) // first, so that a failed test does not hang
	synced, closed := make(chan struct{}), make(chan struct{})
	started := time.Now()
	go func() { outbound.SyncWireGuard([]C.Proxy{p}, true); close(synced) }()
	waitFor(t, entered)
	go func() { outbound.CloseWireGuard(); close(closed) }()
	waitFor(t, synced)
	waitFor(t, closed)
	require.Less(t, time.Since(started), C.DefaultTCPTimeout)
	require.Nil(t, outbound.WireGuardSessionOf(p))
}

// heldTransport cannot connect before hold is closed.
type heldTransport struct {
	localTransport
	hold    chan struct{}
	entered chan struct{} // gets a value when a connect waits
}

func (d heldTransport) wait(ctx context.Context) error {
	select {
	case d.entered <- struct{}{}:
	default:
	}
	select {
	case <-d.hold:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d heldTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := d.wait(ctx); err != nil {
		return nil, err
	}
	return d.localTransport.DialContext(ctx, network, address)
}

func (d heldTransport) ListenPacket(ctx context.Context, network, address string, dst netip.AddrPort) (net.PacketConn, error) {
	if err := d.wait(ctx); err != nil {
		return nil, err
	}
	return d.localTransport.ListenPacket(ctx, network, address, dst)
}

// A device that its caller starts resolves the endpoint names in that start.
func TestWireGuardListenerOwnStart(t *testing.T) {
	withLookup(t)
	port := testPort(t)
	w := makeWG(t, outbound.WireGuardOption{Name: "wg", Ip: "10.8.0.1", PrivateKey: keys(t).private, ListenPort: testPort(t),
		WireGuardPeerOption: outbound.WireGuardPeerOption{PublicKey: keys(t).public, Server: "wg-endpoint.invalid", Port: port}})
	require.NoError(t, w.Start())
	requirePeerField(t, w, fmt.Sprintf("endpoint=127.0.0.1:%d\n", port))
	requirePeerField(t, w, "persistent_keepalive_interval=25\n")
}

// A connection that refreshes the endpoints does not hold up a sync.
func TestWireGuardSyncDuringEndpointRefresh(t *testing.T) {
	lookup := withLookup(t)
	m := listenerOptions(t, testPort(t))
	m["server"], m["port"], m["refresh-server-ip-interval"] = "slow.invalid", testPort(t), 1
	p := parseListener(t, m)
	syncWG(t, p)
	running := session(t, p)
	time.Sleep(1100 * time.Millisecond) // the refresh interval
	hold := make(chan struct{})
	lookup.hold, lookup.held = hold, make(chan struct{}, 1)
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(hold) }) })
	dialed := make(chan struct{})
	go func() {
		defer close(dialed)
		if c, err := p.DialContext(context.Background(), metadata(netip.MustParseAddr("10.8.0.1"), 9)); err == nil {
			_ = c.Close()
		}
	}()
	waitFor(t, lookup.held)
	synced := make(chan struct{})
	go func() { outbound.SyncWireGuard([]C.Proxy{p}, true); close(synced) }()
	waitFor(t, synced)
	require.Same(t, running, session(t, p))
	release.Do(func() { close(hold) })
	waitFor(t, dialed)
}

// waitFor fails the test when ch does not deliver in time.
func waitFor(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}

// A listening socket keeps the routing mark that it was opened with.
func TestWireGuardRoutingMarkChange(t *testing.T) {
	withLoopbackSockets(t, nil) // the hook replaces the mark, which needs a privilege
	port := testPort(t)
	p := parseListener(t, listenerOptions(t, port))
	syncWG(t, p)
	first := session(t, p)
	done := first.TestDeviceDone()
	syncWG(t, p)
	require.Same(t, first, session(t, p))

	// Parsing a config changes the global mark for a moment. Only a sync for
	// an applied config takes the new one.
	prev := dialer.DefaultRoutingMark.Swap(72)
	t.Cleanup(func() { dialer.DefaultRoutingMark.Store(prev) })
	outbound.SyncWireGuard([]C.Proxy{p}, false)
	require.Same(t, first, session(t, p))
	syncWG(t, p)
	checkStopped(t, done)
	require.NotSame(t, first, session(t, p))
	checkPort(t, port, true)
}

// sliceDialer is a dialer from the Go API whose value cannot be compared.
type sliceDialer struct {
	localTransport
	_ []int
}

func TestWireGuardSessionSharing(t *testing.T) {
	var binds atomic.Int32
	withLoopbackSockets(t, func() error { binds.Add(1); return nil })
	m := listenerOptions(t, testPort(t))
	parse := func(options ...adapter.ProxyOption) C.Proxy {
		p, err := adapter.ParseProxy(m, append(options, adapter.WithTunnelForAPI(tunnel.Tunnel))...)
		require.NoError(t, err)
		return p
	}
	// The proxy of a config and the proxy that a reload builds from the same
	// options are one session.
	config, reloaded := parse(), parse()
	syncWG(t, config, reloaded)
	require.EqualValues(t, 2, binds.Load())
	require.Same(t, session(t, config), session(t, reloaded))
	// So is a spelling of the options that means the same.
	m["allow-peer-access"], m["dialer-proxy"], m["persistent-keepalive"] = true, "unused", "0"
	require.Same(t, session(t, config), session(t, parse()))
	syncWG(t)

	// A dialer or a tunnel from the Go API is itself. Only a value that cannot
	// be compared counts by its content.
	p, again := parse(adapter.WithDialerForAPI(sliceDialer{})), parse(adapter.WithDialerForAPI(sliceDialer{}))
	syncWG(t, p)
	own := session(t, p)
	require.Same(t, own, session(t, again))
	syncWG(t, again)
	require.Same(t, own, session(t, p))
	require.Nil(t, outbound.WireGuardSessionOf(parse(adapter.WithDialerForAPI(&sliceDialer{}))))
	other, err := adapter.ParseProxy(m, adapter.WithDialerForAPI(sliceDialer{}), adapter.WithTunnelForAPI(&struct{ C.Tunnel }{tunnel.Tunnel}))
	require.NoError(t, err)
	same, err := adapter.ParseProxy(m, adapter.WithDialerForAPI(sliceDialer{}), adapter.WithTunnelForAPI(&struct{ C.Tunnel }{tunnel.Tunnel}))
	require.NoError(t, err)
	require.Nil(t, outbound.WireGuardSessionOf(other), "another tunnel with the same content")
	syncWG(t, other)
	require.Nil(t, outbound.WireGuardSessionOf(same))
	require.Nil(t, outbound.WireGuardSessionOf(p))
}
