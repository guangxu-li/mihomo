package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/metacubex/mihomo/common/sockopt"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	wireguard "github.com/metacubex/sing-wireguard"
	wgconn "github.com/metacubex/wireguard-go/conn"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Go's syscall package gives these errors different values from Winsock.
const (
	winsockMessageSize  = syscall.Errno(10040)
	winsockNoAddrFamily = syscall.Errno(10047)
	winsockAddressInUse = syscall.Errno(10048)
)

// wgListenBind keeps one wildcard socket per available family. The receive
// functions capture their socket so closing a bind also stops its old readers.
type wgListenBind struct {
	ctx     context.Context
	start   context.Context // limits the first Open
	name    string
	api     C.Dialer
	iface   string
	mark    int
	mu      sync.RWMutex
	sockets [2]*wgSocket
}

// newWGListenBind returns the bind of a listening proxy. The sockets live as
// long as ctx and get mark as their routing mark. start limits their first opening.
func newWGListenBind(ctx, start context.Context, option WireGuardOption, mark int) *wgListenBind {
	return &wgListenBind{ctx: ctx, start: start, name: option.Name, api: option.DialerForAPI, iface: option.Interface, mark: mark}
}

func (b *wgListenBind) openContext() context.Context {
	if b.start != nil {
		return b.start
	}
	return b.ctx
}

func (b *wgListenBind) listen(network, address string) (net.PacketConn, error) {
	ctx := b.openContext()
	if b.api != nil {
		return b.api.ListenPacket(ctx, network, address, netip.AddrPort{})
	}
	lc := net.ListenConfig{Control: dialer.DefaultSocketHook}
	if lc.Control == nil && b.mark != 0 {
		lc.Control = func(_, _ string, raw syscall.RawConn) error { return sockopt.RawConnMark(raw, b.mark) }
	}
	return lc.ListenPacket(ctx, network, address)
}

func wgAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || (runtime.GOOS == "windows" && errors.Is(err, winsockAddressInUse))
}

func (b *wgListenBind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sockets[0] != nil || b.sockets[1] != nil {
		return nil, 0, wgconn.ErrBindAlreadyOpen
	}
	defer func() { b.start = nil }()
	var fns []wgconn.ReceiveFunc
	var listenErr error
	for i, network := range []string{"udp4", "udp6"} {
		pc, err := b.listen(network, net.JoinHostPort("", strconv.Itoa(int(port))))
		if err != nil {
			// As in wireguard-go, only an address family that the system lacks is fine.
			if !errors.Is(err, syscall.EAFNOSUPPORT) && !(runtime.GOOS == "windows" && errors.Is(err, winsockNoAddrFamily)) {
				b.closeSockets()
				return nil, 0, err
			}
			listenErr = err
			continue
		}
		udp, ok := pc.(*net.UDPConn)
		if !ok {
			_ = pc.Close()
			b.closeSockets()
			return nil, 0, fmt.Errorf("WireGuard listen-port needs a UDP socket, got %T", pc)
		}
		b.sockets[i] = newWGSocket(udp, i == 1)
		_ = udp.SetReadBuffer(7 << 20)
		_ = udp.SetWriteBuffer(7 << 20)
		fns = append(fns, b.sockets[i].receive)
	}
	if len(fns) == 0 {
		return nil, 0, listenErr
	}
	b.warnUnsupportedEgress()
	return fns, port, nil
}

// wgReplySrc is where the last datagram of a peer arrived. The reply leaves
// from that address on that interface.
type wgReplySrc struct {
	addr    netip.Addr
	ifIndex int
}

func newWGReplySrc(dst net.IP, ifIndex int) wgReplySrc {
	addr, _ := netip.AddrFromSlice(dst)
	if addr = addr.Unmap(); addr.IsUnspecified() || addr.IsMulticast() {
		addr = netip.Addr{}
	}
	return wgReplySrc{addr, ifIndex}
}

type wgListenEndpoint struct {
	wireguard.Endpoint
	src atomic.Pointer[wgReplySrc]
}

func (e *wgListenEndpoint) ClearSrc() { e.src.Store(nil) }

type wgSocket struct {
	*net.UDPConn
	v4 *ipv4.PacketConn
	v6 *ipv6.PacketConn
}

func newWGSocket(c *net.UDPConn, v6 bool) *wgSocket {
	s := &wgSocket{UDPConn: c}
	if v6 {
		pc := ipv6.NewPacketConn(c)
		if pc.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true) == nil {
			s.v6 = pc
		}
	} else {
		pc := ipv4.NewPacketConn(c)
		if pc.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true) == nil {
			s.v4 = pc
		}
	}
	return s
}

// canSelectInterface reports whether a write can name the interface. For
// IPv4, golang.org/x/net sends that control message on these systems only.
func (s *wgSocket) canSelectInterface() bool {
	return s.v6 != nil || s.v4 != nil && (runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "solaris")
}

func (s *wgSocket) receive(packets [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
	var n int
	var from wgReplySrc
	var src net.Addr
	var err error
	switch {
	case s.v4 != nil:
		var cm *ipv4.ControlMessage
		n, cm, src, err = s.v4.ReadFrom(packets[0])
		if cm != nil {
			from = newWGReplySrc(cm.Dst, cm.IfIndex)
		}
	case s.v6 != nil:
		var cm *ipv6.ControlMessage
		n, cm, src, err = s.v6.ReadFrom(packets[0])
		if cm != nil {
			from = newWGReplySrc(cm.Dst, cm.IfIndex)
		}
	default:
		n, src, err = s.ReadFrom(packets[0])
	}
	if err != nil {
		// Winsock consumes a truncated datagram and reports WSAEMSGSIZE.
		if errors.Is(err, syscall.EMSGSIZE) || (runtime.GOOS == "windows" && errors.Is(err, winsockMessageSize)) {
			return 0, nil
		}
		return 0, err
	}
	sizes[0] = n
	ap := src.(*net.UDPAddr).AddrPort()
	ep := &wgListenEndpoint{Endpoint: wireguard.Endpoint(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))}
	if from != (wgReplySrc{}) {
		ep.src.Store(&from)
	}
	eps[0] = ep
	return 1, nil
}

// write sends p from src. A zero src leaves the choice to the system.
func (s *wgSocket) write(p []byte, remote *net.UDPAddr, src wgReplySrc) error {
	var err error
	switch {
	case src != (wgReplySrc{}) && s.v4 != nil:
		_, err = s.v4.WriteTo(p, &ipv4.ControlMessage{Src: src.addr.AsSlice(), IfIndex: src.ifIndex}, remote)
	case src != (wgReplySrc{}) && s.v6 != nil:
		_, err = s.v6.WriteTo(p, &ipv6.ControlMessage{Src: src.addr.AsSlice(), IfIndex: src.ifIndex}, remote)
	default:
		_, err = s.WriteToUDP(p, remote)
	}
	return err
}

func (b *wgListenBind) closeSockets() {
	for i, s := range b.sockets {
		if s != nil {
			_ = s.Close()
			b.sockets[i] = nil
		}
	}
}

func (b *wgListenBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeSockets()
	return nil
}

func (b *wgListenBind) Send(bufs [][]byte, endpoint wgconn.Endpoint) error {
	ep := endpoint.(*wgListenEndpoint)
	remote := netip.AddrPort(ep.Endpoint)
	family := 0
	if remote.Addr().Is6() {
		family = 1
	}
	b.mu.RLock()
	udp := b.sockets[family]
	b.mu.RUnlock()
	if udp == nil {
		return net.ErrClosed
	}
	dst := net.UDPAddrFromAddrPort(remote)
	for _, p := range bufs {
		if src := ep.src.Load(); src != nil && udp.write(p, dst, *src) == nil {
			continue
		}
		ep.ClearSrc()
		index, err := b.outputInterface(remote.Addr())
		if err != nil {
			return err
		}
		if err := udp.write(p, dst, wgReplySrc{ifIndex: index}); err != nil {
			return err
		}
	}
	return nil
}

// warnUnsupportedEgress tells that an egress interface is set, but a socket
// cannot choose the interface for each datagram on this system.
func (b *wgListenBind) warnUnsupportedEgress() {
	if dialer.DefaultSocketHook != nil || b.iface == "" && dialer.DefaultInterface.Load() == "" && dialer.DefaultInterfaceFinder.Load() == nil {
		return
	}
	for _, s := range b.sockets {
		if s != nil && !s.canSelectInterface() {
			log.Warnln("[WG](%s) the listening socket cannot follow interface-name on %s", b.name, runtime.GOOS)
			return
		}
	}
}

// Select the sending interface per datagram so the socket can receive on any interface.
func (b *wgListenBind) outputInterface(dst netip.Addr) (int, error) {
	if !dst.IsGlobalUnicast() || dialer.DefaultSocketHook != nil {
		return 0, nil
	}
	name := b.iface
	if name == "" {
		name = dialer.DefaultInterface.Load()
	}
	if name == "" {
		if finder := dialer.DefaultInterfaceFinder.Load(); finder != nil {
			name = finder.FindInterfaceName(dst)
		}
	}
	if name == "" {
		return 0, nil
	}
	it, err := iface.ResolveInterface(name)
	if err != nil {
		return 0, err
	}
	return it.Index, nil
}

func (b *wgListenBind) BatchSize() int       { return 1 }
func (b *wgListenBind) SetMark(uint32) error { return nil } // applied at socket creation
func (b *wgListenBind) ParseEndpoint(s string) (wgconn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	return &wgListenEndpoint{Endpoint: wireguard.Endpoint(netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()))}, err
}
