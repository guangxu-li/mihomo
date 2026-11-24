package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/mipstack"
	wireguard "github.com/metacubex/sing-wireguard"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	network "github.com/metacubex/sing/common/network"
	wgconn "github.com/metacubex/wireguard-go/conn"
	"golang.org/x/exp/slices"
)

// Peer access lets the peers of a WireGuard proxy open connections through the
// tunnel. This file holds what a WireGuard device needs for it. The sessions
// that a config keeps running are in wireguard_session.go.

// preparePeerAccess checks the peer-access options and gives them the form
// that NewWireGuard expects. It changes nothing for a proxy without them.
func (option *WireGuardOption) preparePeerAccess() error {
	option.AllowPeerAccess = option.AllowPeerAccess || option.AcceptIncoming || option.ListenPort != 0
	option.AcceptIncoming = false
	if !option.AllowPeerAccess {
		return nil
	}
	if option.ProviderName != "" { // the author of a provider must not get access to this device
		return errors.New("allow-peer-access and listen-port are not supported in a proxy provider")
	}
	if option.ListenPort < 0 || option.ListenPort > 65535 {
		return errors.New("listen-port must be between 1 and 65535")
	}
	if option.ListenPort != 0 {
		if option.AmneziaWGOption != nil {
			return errors.New("amnezia-wg-option is not supported with listen-port")
		}
		if len(option.Reserved) != 0 || slices.ContainsFunc(option.Peers, func(peer WireGuardPeerOption) bool { return len(peer.Reserved) != 0 }) {
			return errors.New("reserved is not supported with listen-port")
		}
		option.DialerProxy = "" // peers have to reach the port on this device
	}
	option.IPStack.forward = true

	// NewWireGuard rewrites the keys below in place.
	if option.AmneziaWGOption != nil {
		amnezia := *option.AmneziaWGOption
		option.AmneziaWGOption = &amnezia
	}
	// The top-level persistent-keepalive is for every peer that has none of its own.
	explicit := option.Keepalive != nil || option.PersistentKeepalive != 0
	keepalive, err := wgKeepalive(option.Keepalive, option.PersistentKeepalive)
	if err != nil {
		return err
	}
	option.PersistentKeepalive, option.Keepalive = keepalive, nil

	if len(option.Peers) != 0 {
		option.Peers = slices.Clone(option.Peers)
	} else {
		peer := option.WireGuardPeerOption
		if len(peer.AllowedIPs) == 0 {
			// As without peer access, the single peer gets every address.
			prefixes, err := option.Prefixes()
			if err != nil {
				return err
			}
			if slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Addr().Unmap().Is4() }) {
				peer.AllowedIPs = append(peer.AllowedIPs, "0.0.0.0/0")
			}
			if slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return !p.Addr().Unmap().Is4() }) {
				peer.AllowedIPs = append(peer.AllowedIPs, "::/0")
			}
		}
		option.Peers = []WireGuardPeerOption{peer}
	}

	keys := make(map[string]bool, len(option.Peers))
	endpoints := make(map[M.Socksaddr]bool, len(option.Peers))
	for i := range option.Peers {
		peer := &option.Peers[i]
		switch {
		case peer.Server == "" && peer.Port == 0:
			if option.ListenPort == 0 {
				return fmt.Errorf("peer %d has no server and port, which requires listen-port", i)
			}
		case peer.Server == "" || peer.Port < 1 || peer.Port > 65535:
			return fmt.Errorf("peer %d requires a server and a port between 1 and 65535", i)
		case endpoints[peer.Addr()]:
			// One WireGuard device has one key, so only one of the two peers could answer there.
			return fmt.Errorf("peer %d has the same server and port as another peer", i)
		default:
			endpoints[peer.Addr()] = true
		}
		// NewWireGuard reports a key that cannot be decoded.
		if key, err := base64.StdEncoding.DecodeString(peer.PublicKey); err == nil {
			if len(key) != 32 {
				return fmt.Errorf("peer %d requires a public-key of 32 bytes", i)
			}
			if keys[string(key)] {
				return fmt.Errorf("peer %d has the same public-key as another peer", i)
			}
			keys[string(key)] = true
		}
		for _, allowedIP := range peer.AllowedIPs {
			if _, err := netip.ParsePrefix(allowedIP); err != nil {
				return fmt.Errorf("peer %d allowed-ips: %w", i, err)
			}
		}
		interval := keepalive
		if peer.Keepalive != nil {
			if interval, err = wgKeepalive(peer.Keepalive, 0); err != nil {
				return fmt.Errorf("peer %d: %w", i, err)
			}
		} else if !explicit && peer.Server != "" {
			interval = 25 // keeps the NAT mapping open for the remote side
		}
		peer.Keepalive = interval
	}
	return nil
}

// wgKeepalive returns the persistent-keepalive that value holds, or unset when
// value is nil. It reads a number the way the proxy decoder does. A proxy
// without peer access ignores the key of a peer, so the key is not decoded
// with the other options.
func wgKeepalive(value any, unset int) (int, error) {
	option := struct {
		Interval int64 `proxy:"persistent-keepalive"` // wide, so that the range check sees the whole number
	}{int64(unset)}
	if value != nil {
		decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
		if err := decoder.Decode(map[string]any{"persistent-keepalive": value}, &option); err != nil {
			return 0, err
		}
	}
	if option.Interval < 0 || option.Interval > 65535 {
		return 0, errors.New("persistent-keepalive must be between 0 and 65535")
	}
	return int(option.Interval), nil
}

// keepalive returns the persistent keepalive interval for a new peer of the
// device. A peer whose endpoint is still to be resolved gets it with the
// endpoint, see endpointConf.
func (w *WireGuard) keepalive(peer WireGuardPeerOption, endpoint netip.AddrPort) int {
	if !w.option.AllowPeerAccess {
		return w.option.PersistentKeepalive
	}
	if peer.Server != "" && !endpoint.IsValid() {
		return 0
	}
	return peer.Keepalive.(int)
}

// endpointConf returns the endpoint of a peer for the device. A listening
// proxy may have none yet. When refreshEndpoints adds it later, the keepalive
// comes with it: the device then sends one at once, which starts the handshake.
func (w *WireGuard) endpointConf(peer WireGuardPeerOption, endpoint netip.AddrPort, update bool) string {
	if !endpoint.IsValid() {
		return ""
	}
	conf := "endpoint=" + endpoint.String() + "\n"
	if update && w.option.ListenPort != 0 {
		if keepalive := w.keepalive(peer, endpoint); keepalive != 0 {
			conf += fmt.Sprintf("persistent_keepalive_interval=%d\n", keepalive)
		}
	}
	return conf
}

// deviceBind returns the bind for a new WireGuard device. With listen-port all
// peers share one listening socket, which the device closes with itself. ctx
// limits the first opening of that socket.
func (w *WireGuard) deviceBind(ctx context.Context) wgconn.Bind {
	if w.option.ListenPort == 0 {
		return w.bind
	}
	egress := w.egress // of the applied config, see SyncWireGuard
	if egress == nil {
		now := wgEgressOf(w.option, wgGlobalEgress())
		egress = &now
	}
	return newWGListenBind(w.runCtx, ctx, w.option, egress.mark)
}

// acceptPeers hands the connections that peers open through stack to the
// tunnel. Rules see them as inbound type WIREGUARD with the proxy's name.
func (w *WireGuard) acceptPeers(stack ipStack) error {
	tunnel := w.option.NewTunnel()
	if tunnel == nil {
		return errors.New("WireGuard peer access requires a tunnel")
	}
	dns := wgDNS{NewDnsWithOption(DnsOption{Name: "DNS"})}
	handler, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel: tunnel,
		Type:   C.WIREGUARD,
		Additions: []inbound.Addition{inbound.WithInName(w.Name()), func(metadata *C.Metadata) {
			if !w.loopbackFor(metadata.DstIP).IsValid() {
				return
			}
			metadata.InboundLocal = w
			if metadata.DstPort == 53 && resolver.DefaultService.Load() != nil {
				metadata.InboundLocal = dns
			}
		}},
	})
	if err != nil {
		return err
	}
	w.peerRoutes = w.option.peerRoutes()
	switch stack := stack.(type) {
	case wireguard.RegisterForward:
		return stack.RegisterForward(wireguard.ForwardOptions{Handler: handler})
	case *mipstack.Stack:
		return registerMipsForward(w.runCtx, stack, handler)
	default:
		return fmt.Errorf("WireGuard peer access is not supported on %T", stack)
	}
}

func registerMipsForward(ctx context.Context, stack *mipstack.Stack, handler wireguard.ForwardHandler) error {
	_, err := mipstack.NewTCPForwarder(stack, mipstack.TCPForwarderOptions{}, func(r *mipstack.TCPForwarderRequest) {
		c, err := r.Accept(ctx)
		if err != nil {
			return
		}
		defer c.Close()
		_ = handler.NewConnection(ctx, c, wgFlowMetadata(r.Flow()))
	})
	if err != nil {
		return err
	}
	_, err = mipstack.NewUDPForwarder(stack, mipstack.UDPForwarderOptions{}, func(r *mipstack.UDPForwarderRequest) {
		responder, err := r.DetachForReplies()
		if err != nil {
			return
		}
		payload := r.Payload()
		b := buf.NewSize(len(payload))
		_, _ = b.Write(payload)
		handler.NewPacket(ctx, r.Flow().Source, b, wgFlowMetadata(r.Flow()), func(network.PacketConn) network.PacketWriter { return wgReplyWriter{responder} })
	})
	return err
}

func wgFlowMetadata(flow mipstack.ForwarderFlow) M.Metadata {
	return M.Metadata{Source: M.SocksaddrFromNetIP(flow.Source), Destination: M.SocksaddrFromNetIP(flow.Destination)}
}

type wgReplyWriter struct {
	*mipstack.UDPForwarderResponder
}

func (w wgReplyWriter) WritePacket(b *buf.Buffer, src M.Socksaddr) error {
	defer b.Release()
	_, err := w.ReplyFrom(b.Bytes(), src.AddrPort())
	return err
}

// wgDNS answers DNS queries to the proxy's own address. A peer is not a local
// client, so an idle TCP stream times out as it does for the TUN listener.
type wgDNS struct {
	*Dns
}

func (d wgDNS) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	left, right := N.Pipe()
	go resolver.RelayDnsConn(context.Background(), right, resolver.DefaultDnsReadTimeout)
	return NewConn(left, d), nil
}

// loopbackFor returns the loopback address that stands for dst on this host.
// It is valid only when dst is one of the proxy's own addresses.
func (w *WireGuard) loopbackFor(dst netip.Addr) netip.Addr {
	dst = dst.Unmap()
	for _, prefix := range w.localPrefixes {
		if prefix.Addr().Unmap() == dst {
			if dst.Is4() {
				return netip.AddrFrom4([4]byte{127, 0, 0, 1})
			}
			return netip.IPv6Loopback()
		}
	}
	return netip.Addr{}
}

// wgLocalDevice delivers a connection to the proxy's own address to the local
// host. Any other connection goes through the tunnel, unless its peer has no
// endpoint yet.
type wgLocalDevice struct {
	wireguardDevice
	w *WireGuard
}

func (d wgLocalDevice) DialTCP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error) {
	if loopback := d.w.loopbackFor(destination.Addr()); loopback.IsValid() {
		return (&net.Dialer{}).DialContext(ctx, "tcp", netip.AddrPortFrom(loopback, destination.Port()).String())
	}
	if err := d.w.checkEndpoint(destination.Addr()); err != nil {
		return nil, err
	}
	return d.wireguardDevice.DialTCP(ctx, network, source, destination)
}

// dialOwnAddress connects to the local host when the destination is the
// proxy's own address. It returns nil when the connection belongs to the tunnel.
func (w *WireGuard) dialOwnAddress(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if !w.loopbackFor(metadata.DstIP).IsValid() {
		return nil, nil
	}
	conn, err := w.tunDevice.DialTCP(ctx, "tcp", netip.AddrPort{}, metadata.AddrPort())
	if err != nil {
		return nil, err
	}
	return NewConn(conn, w), nil
}

// listenOwnAddress serves a UDP association to the proxy's own address from
// the local host. It returns nil when the association belongs to the tunnel.
// The first destination decides for the whole association.
func (w *WireGuard) listenOwnAddress(metadata *C.Metadata) (C.PacketConn, error) {
	loopback := w.loopbackFor(metadata.DstIP)
	if !loopback.IsValid() {
		return nil, w.checkEndpoint(metadata.DstIP)
	}
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopback, 0)))
	if err != nil {
		return nil, err
	}
	return NewPacketConn(&wgLoopbackPacketConn{pc, metadata.DstIP.Unmap(), loopback}, w), nil
}

// A local UDP service sees loopback. Its peer sees the proxy's own address.
type wgLoopbackPacketConn struct {
	*net.UDPConn
	own, loopback netip.Addr
}

func (c *wgLoopbackPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dst := M.AddrPortFromNet(addr)
	if dst.Addr().Unmap() != c.own {
		return 0, net.InvalidAddrError("not the WireGuard proxy's own address")
	}
	return c.WriteToUDPAddrPort(p, netip.AddrPortFrom(c.loopback, dst.Port()))
}

func (c *wgLoopbackPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, src, err := c.ReadFromUDPAddrPort(p)
		if err != nil {
			return 0, nil, err
		}
		if src.Addr().Unmap() == c.loopback {
			return n, net.UDPAddrFromAddrPort(netip.AddrPortFrom(c.own, src.Port())), nil
		}
	}
}

// listenEndpoint returns the endpoint of a peer of a listening proxy. It is
// invalid when the peer has none, and when its name is not resolved. The
// device then works without it: the peer's first handshake sets the endpoint,
// or refreshEndpoints does. A session (a device with an egress) looks no name
// up before its device listens, so that it listens however long a lookup takes.
func (w *WireGuard) listenEndpoint(ctx context.Context, address M.Socksaddr) netip.AddrPort {
	if !address.IsValid() || w.egress != nil && !w.initOk.Load() {
		return netip.AddrPort{}
	}
	udpAddr, err := resolveUDPAddr(ctx, "udp", address.String(), w.prefer)
	if err != nil {
		log.Warnln("[WG](%s) resolve endpoint %s: %s", w.Name(), address, err)
		return w.serverAddrMap[address] // what the device has
	}
	addrPort := udpAddr.AddrPort()
	return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
}

// refreshEndpoints looks up the endpoint names that have no address yet, and
// gives the device the ones that resolve. It reports whether none is left.
func (w *WireGuard) refreshEndpoints(ctx context.Context) (bool, error) {
	if !w.serverAddrMutex.TryLock() { // a connection refreshes them now, see updateServerAddr
		return false, nil
	}
	defer w.serverAddrMutex.Unlock()
	var pending []WireGuardPeerOption
	for _, peer := range w.option.Peers {
		if peer.Server != "" && !w.serverAddrMap[peer.Addr()].IsValid() {
			pending = append(pending, peer)
		}
	}
	ipcConf := ""
	resolved := make(map[M.Socksaddr]netip.AddrPort, len(pending))
	for i, peer := range pending {
		// The names that are left share the time that is left, so that one
		// that does not answer leaves time for the others.
		lookup, cancel := ctx, context.CancelFunc(func() {})
		if deadline, ok := ctx.Deadline(); ok {
			lookup, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(pending)-i))
		}
		endpoint := w.listenEndpoint(lookup, peer.Addr())
		cancel()
		if endpoint.IsValid() {
			resolved[peer.Addr()] = endpoint
			ipcConf += "public_key=" + peer.PublicKey + "\nupdate_only=true\n" + w.endpointConf(peer, endpoint, true)
		}
	}
	if ipcConf != "" {
		if err := w.device.IpcSet(ipcConf); err != nil {
			return false, err // nothing is noted, so the device gets it all again
		}
		for address, endpoint := range resolved {
			w.serverAddrMap[address] = endpoint
		}
	}
	return len(resolved) == len(pending), nil
}

// wgPeerRoute is one allowed-ips prefix of a peer of a listening proxy.
type wgPeerRoute struct {
	prefix netip.Prefix
	peer   *wgPeerEndpoint
}

// wgPeerEndpoint tells whether the device has an endpoint for a peer.
type wgPeerEndpoint struct {
	publicKey string
	known     atomic.Bool
}

func (option WireGuardOption) peerRoutes() (routes []wgPeerRoute) {
	if option.ListenPort == 0 { // every peer has an endpoint
		return nil
	}
	for _, peer := range option.Peers {
		endpoint := &wgPeerEndpoint{publicKey: peer.PublicKey}
		for _, allowedIP := range peer.AllowedIPs {
			if prefix, err := netip.ParsePrefix(allowedIP); err == nil { // the device rejects the others
				routes = append(routes, wgPeerRoute{prefix, endpoint})
			}
		}
	}
	return routes
}

// checkEndpoint fails when dst belongs to a peer that has no endpoint yet, so
// that the connection does not wait for its timeout.
func (w *WireGuard) checkEndpoint(dst netip.Addr) error {
	dst = dst.Unmap()
	var peer *wgPeerEndpoint
	best := -1
	for _, route := range w.peerRoutes {
		if route.prefix.Bits() >= best && route.prefix.Contains(dst) {
			best, peer = route.prefix.Bits(), route.peer
		}
	}
	// The device keeps an endpoint for its lifetime and follows the peer when it roams.
	if peer == nil || peer.known.Load() {
		return nil
	}
	conf, err := w.device.IpcGet()
	if err != nil {
		return err
	}
	_, block, ok := strings.Cut(conf, "public_key="+peer.publicKey+"\n")
	if ok {
		block, _, _ = strings.Cut(block, "public_key=")
		if strings.Contains("\n"+block, "\nendpoint=") {
			peer.known.Store(true)
			return nil
		}
	}
	return fmt.Errorf("%w for %s", C.ErrNoWireGuardEndpoint, dst)
}
