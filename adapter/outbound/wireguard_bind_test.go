package outbound

import (
	"context"
	"crypto/rand"
	"math/big"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/log"
	wgconn "github.com/metacubex/wireguard-go/conn"
	"github.com/stretchr/testify/require"
)

type wgTestFinder string

func (f wgTestFinder) FindInterfaceName(netip.Addr) string { return string(f) }

func wgTestLoopbackInterface(t *testing.T) net.Interface {
	t.Helper()
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, it := range interfaces {
		if it.Flags&net.FlagLoopback != 0 {
			return it
		}
	}
	t.Fatal("no loopback interface found")
	return net.Interface{}
}

func wgTestFreeUDPPort(t *testing.T) uint16 {
	t.Helper()
	lo := netip.MustParseAddr("127.0.0.1")
	for i := 0; i < 64; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10000)) // below the usual WireGuard ports
		require.NoError(t, err)
		port := uint16(36000 + n.Int64())
		c4, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(lo, port)))
		if err != nil {
			continue
		}
		_ = c4.Close()
		c6, err := net.ListenUDP("udp6", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), port)))
		if err != nil {
			continue
		}
		_ = c6.Close()
		return port
	}
	t.Fatal("no free test UDP port")
	return 0
}

func TestWireGuardSocketPolicy(t *testing.T) {
	lo := wgTestLoopbackInterface(t)

	oldDefault := dialer.DefaultInterfaceFinder.Swap(wgTestFinder(lo.Name))
	oldIface := dialer.DefaultInterface.Swap("")
	t.Cleanup(func() {
		dialer.DefaultInterfaceFinder.Store(oldDefault)
		dialer.DefaultInterface.Store(oldIface)
	})
	b := newWGListenBind(context.Background(), context.Background(), WireGuardOption{Name: "wg-policy"}, 0)
	dst := netip.MustParseAddr("192.0.2.1")
	idx, err := b.outputInterface(dst)
	require.NoError(t, err)
	require.Equal(t, lo.Index, idx)
	b.iface = "missing-wg-test-interface"
	_, err = b.outputInterface(dst)
	require.Error(t, err)
	for _, address := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6LinkLocalAllNodes()} {
		idx, err := b.outputInterface(address)
		require.NoError(t, err)
		require.Zero(t, idx)
	}
	// A configured egress interface must not constrain the receiving socket.
	c, err := b.listen("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	_ = c.Close()
	oldHook := dialer.DefaultSocketHook
	called := false
	dialer.DefaultSocketHook = func(_, _ string, _ syscall.RawConn) error { called = true; return nil }
	t.Cleanup(func() { dialer.DefaultSocketHook = oldHook })
	b.mark = 123
	c, err = b.listen("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	_ = c.Close()
	require.True(t, called)

	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			local := netip.MustParseAddrPort(address)
			socket, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(local))
			require.NoError(t, err)
			defer socket.Close()
			target := socket.LocalAddr().(*net.UDPAddr).AddrPort()
			s := newWGSocket(socket, local.Addr().Is6())
			family := 0
			if local.Addr().Is6() {
				family = 1
			}
			b.sockets[family] = s
			ep, err := b.ParseEndpoint(target.String())
			require.NoError(t, err)
			reply := ep.(*wgListenEndpoint)
			stale := wgReplySrc{addr: local.Addr(), ifIndex: 1 << 30} // simulate removal of the receiving interface
			reply.src.Store(&stale)
			if runtime.GOOS == "linux" {
				require.Error(t, s.write([]byte("wg"), net.UDPAddrFromAddrPort(target), stale))
			}
			require.NoError(t, b.Send([][]byte{[]byte("wg")}, reply))
			if runtime.GOOS == "linux" {
				require.Nil(t, reply.src.Load())
			}
			require.NoError(t, s.SetReadDeadline(time.Now().Add(time.Second)))
			packets, sizes, eps := [][]byte{make([]byte, 32)}, []int{0}, make([]wgconn.Endpoint, 1)
			n, err := s.receive(packets, sizes, eps)
			require.NoError(t, err)
			require.Equal(t, 1, n)
			require.Equal(t, "wg", string(packets[0][:sizes[0]]))
			received := eps[0].(*wgListenEndpoint)
			require.Equal(t, target, netip.AddrPort(received.Endpoint))
			if runtime.GOOS == "linux" {
				gotSrc := received.src.Load()
				require.NotNil(t, gotSrc)
				require.Equal(t, lo.Index, gotSrc.ifIndex)
				require.Equal(t, local.Addr(), gotSrc.addr)
			}
			eps[0].ClearSrc()
			require.Nil(t, received.src.Load())
		})
	}
}

func TestWGListenBindReplySourceOnSecondAddress(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("127.0.0.2 loopback alias requires Linux")
	}
	lo := wgTestLoopbackInterface(t)
	b := newWGListenBind(context.Background(), context.Background(), WireGuardOption{Name: "wg-reply-src"}, 0)
	port := wgTestFreeUDPPort(t)
	fns, bound, err := b.Open(port)
	require.NoError(t, err)
	require.Equal(t, port, bound)
	defer b.Close()

	peerAddr := netip.MustParseAddr("127.0.0.1")
	contacted := netip.MustParseAddr("127.0.0.2")
	client, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerAddr, 0)))
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	require.NoError(t, b.sockets[0].SetReadDeadline(time.Now().Add(2*time.Second)))

	_, err = client.WriteToUDPAddrPort([]byte("request"), netip.AddrPortFrom(contacted, port))
	require.NoError(t, err)

	packets := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	eps := make([]wgconn.Endpoint, 1)
	n, err := fns[0](packets, sizes, eps)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	ep := eps[0].(*wgListenEndpoint)
	gotSrc := ep.src.Load()
	require.NotNil(t, gotSrc)
	require.Equal(t, contacted, gotSrc.addr)
	require.Equal(t, lo.Index, gotSrc.ifIndex)

	require.NoError(t, b.Send([][]byte{[]byte("reply")}, ep))
	buf := make([]byte, 64)
	rn, from, err := client.ReadFromUDPAddrPort(buf)
	require.NoError(t, err)
	require.Equal(t, "reply", string(buf[:rn]))
	require.Equal(t, contacted, from.Addr().Unmap())
	require.Equal(t, port, from.Port())

	// Simulate the local address being removed while the interface stays up:
	// Send must clear both address and interface and fall back cleanly.
	staleAddr := wgReplySrc{addr: netip.MustParseAddr("192.0.2.254"), ifIndex: lo.Index}
	ep.src.Store(&staleAddr)
	require.Error(t, b.sockets[0].write([]byte("reply2"), net.UDPAddrFromAddrPort(netip.AddrPort(ep.Endpoint)), staleAddr))
	require.NoError(t, b.Send([][]byte{[]byte("reply2")}, ep))
	require.Nil(t, ep.src.Load())
	rn, _, err = client.ReadFromUDPAddrPort(buf)
	require.NoError(t, err)
	require.Equal(t, "reply2", string(buf[:rn]))
}

type wgBindCancelDialer struct {
	blockNetwork string
	entered      chan struct{}
	calls        atomic.Int32
	once         sync.Once
	mu           sync.Mutex
	lastCtx      context.Context
}

func (d *wgBindCancelDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (d *wgBindCancelDialer) ListenPacket(ctx context.Context, network, address string, _ netip.AddrPort) (net.PacketConn, error) {
	d.calls.Add(1)
	d.mu.Lock()
	d.lastCtx = ctx
	d.mu.Unlock()
	if network == d.blockNetwork {
		d.once.Do(func() { close(d.entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	host := "127.0.0.1"
	if network == "udp6" {
		host = "::1"
	}
	_, port, _ := net.SplitHostPort(address)
	return net.ListenPacket(network, net.JoinHostPort(host, port))
}

func TestWGListenBindStartContextCancelsOpen(t *testing.T) {
	// Cancelling start during udp4 must abort Open immediately without calling udp6.
	d1 := &wgBindCancelDialer{blockNetwork: "udp4", entered: make(chan struct{})}
	start1, cancel1 := context.WithCancel(context.Background())
	b1 := newWGListenBind(context.Background(), start1, WireGuardOption{
		Name:        "wg-cancel-v4",
		BasicOption: BasicOption{DialerForAPI: d1},
	}, 0)
	errCh := make(chan error, 1)
	go func() {
		_, _, err := b1.Open(wgTestFreeUDPPort(t))
		errCh <- err
	}()
	<-d1.entered
	cancel1()
	require.ErrorIs(t, <-errCh, context.Canceled)
	require.EqualValues(t, 1, d1.calls.Load())
	require.NoError(t, b1.Close())

	// Cancelling start during udp6 after udp4 opened must close udp4 and return the error.
	d2 := &wgBindCancelDialer{blockNetwork: "udp6", entered: make(chan struct{})}
	start2, cancel2 := context.WithCancel(context.Background())
	port2 := wgTestFreeUDPPort(t)
	b2 := newWGListenBind(context.Background(), start2, WireGuardOption{
		Name:        "wg-cancel-v6",
		BasicOption: BasicOption{DialerForAPI: d2},
	}, 0)
	go func() {
		_, _, err := b2.Open(port2)
		errCh <- err
	}()
	<-d2.entered
	cancel2()
	require.ErrorIs(t, <-errCh, context.Canceled)
	// Confirm udp4 socket was closed on cancellation.
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port2)})
	require.NoError(t, err)
	_ = pc.Close()

	// After a successful first Open, b.start is cleared so a subsequent Open uses b.ctx.
	d3 := &wgBindCancelDialer{}
	runCtx := context.WithValue(context.Background(), struct{}{}, "run")
	start3 := context.WithValue(context.Background(), struct{}{}, "start")
	b3 := newWGListenBind(runCtx, start3, WireGuardOption{
		Name:        "wg-start-cleared",
		BasicOption: BasicOption{DialerForAPI: d3},
	}, 0)
	_, _, err = b3.Open(wgTestFreeUDPPort(t))
	require.NoError(t, err)
	d3.mu.Lock()
	require.Equal(t, start3, d3.lastCtx)
	d3.mu.Unlock()
	require.NoError(t, b3.Close())

	_, _, err = b3.Open(wgTestFreeUDPPort(t))
	require.NoError(t, err)
	d3.mu.Lock()
	require.Equal(t, runCtx, d3.lastCtx)
	d3.mu.Unlock()
	require.NoError(t, b3.Close())
}

func TestWGListenBindUnsupportedEgressWarns(t *testing.T) {
	oldLevel := log.Level()
	log.SetLevel(log.WARNING)
	t.Cleanup(func() { log.SetLevel(oldLevel) })

	oldHook := dialer.DefaultSocketHook
	dialer.DefaultSocketHook = nil
	oldDefaultIface := dialer.DefaultInterface.Swap("")
	oldFinder := dialer.DefaultInterfaceFinder.Swap(nil)
	t.Cleanup(func() {
		dialer.DefaultSocketHook = oldHook
		dialer.DefaultInterface.Store(oldDefaultIface)
		dialer.DefaultInterfaceFinder.Store(oldFinder)
	})

	sub := log.Subscribe()
	t.Cleanup(func() { log.UnSubscribe(sub) })

	// log.Subscribe delivers events asynchronously in FIFO order over logCh, so
	// emit a sentinel warning and drain until it arrives for deterministic counts.
	var seq int
	countWarnings := func(tag string, fn func()) int {
		t.Helper()
		seq++
		marker := "wg-bind-warn-sentinel-" + tag + "-" + string(rune('0'+seq))
		fn()
		log.Warnln("%s", marker)
		count := 0
		deadline := time.After(2 * time.Second)
		for {
			select {
			case ev := <-sub:
				if ev.LogLevel == log.WARNING {
					if strings.Contains(ev.Payload, marker) {
						return count
					}
					if strings.Contains(ev.Payload, tag) {
						count++
					}
				}
			case <-deadline:
				t.Fatalf("timed out waiting for log sentinel %s", marker)
			}
		}
	}

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer udp.Close()

	// Socket without PacketConn control-message support simulates platforms like Windows.
	plainSock := &wgSocket{UDPConn: udp}
	require.False(t, plainSock.canSelectInterface())

	// No egress interface configured: no warning.
	bNone := newWGListenBind(context.Background(), context.Background(), WireGuardOption{Name: "wg-warn-none"}, 0)
	bNone.sockets[0] = plainSock
	require.Equal(t, 0, countWarnings("wg-warn-none", bNone.warnUnsupportedEgress))

	// Explicit interface configured: one warning for each opening.
	bIface := newWGListenBind(context.Background(), context.Background(), WireGuardOption{
		Name:        "wg-warn-once",
		BasicOption: BasicOption{Interface: "eth0"},
	}, 0)
	bIface.sockets[0] = plainSock
	require.Equal(t, 1, countWarnings("wg-warn-once", bIface.warnUnsupportedEgress))

	// DefaultSocketHook overrides interface-name: no warning.
	dialer.DefaultSocketHook = func(_, _ string, _ syscall.RawConn) error { return nil }
	bHook := newWGListenBind(context.Background(), context.Background(), WireGuardOption{
		Name:        "wg-warn-hook",
		BasicOption: BasicOption{Interface: "eth0"},
	}, 0)
	bHook.sockets[0] = plainSock
	require.Equal(t, 0, countWarnings("wg-warn-hook", bHook.warnUnsupportedEgress))
	dialer.DefaultSocketHook = nil

	// On Linux, a real newWGSocket supports per-datagram interface selection: no warning.
	if runtime.GOOS == "linux" {
		realSock := newWGSocket(udp, false)
		require.True(t, realSock.canSelectInterface())
		bLinux := newWGListenBind(context.Background(), context.Background(), WireGuardOption{
			Name:        "wg-warn-linux",
			BasicOption: BasicOption{Interface: "eth0"},
		}, 0)
		bLinux.sockets[0] = realSock
		require.Equal(t, 0, countWarnings("wg-warn-linux", bLinux.warnUnsupportedEgress))
	}
}
