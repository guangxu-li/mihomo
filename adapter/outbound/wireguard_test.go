package outbound

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	wireguard "github.com/metacubex/sing-wireguard"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

// Start brings up the device of a WireGuard that a test owns itself.
func (w *WireGuard) Start() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return w.init0(ctx)
}

func (w *WireGuard) TestPeerState() (string, error) {
	if !w.initOk.Load() {
		return "", errors.New("WireGuard is not running")
	}
	return w.device.IpcGet()
}

func (w *WireGuard) TestDialIP(src, dst netip.Addr) (net.Conn, error) {
	network := "ip4:icmp"
	if dst.Is6() {
		network = "ip6:ipv6-icmp"
	}
	if !w.initOk.Load() {
		return nil, errors.New("WireGuard is not running")
	}
	return w.tunDevice.DialIP(context.Background(), network, src, dst)
}

// TestDeviceDone lets an integration test wait for the actual crypto workers.
func (w *WireGuard) TestDeviceDone() <-chan struct{} {
	if !w.initOk.Load() {
		return nil
	}
	return w.device.(interface{ Wait() chan struct{} }).Wait()
}

func HasWireGuardPeerAccess(proxy C.Proxy) bool { return wireGuardPeerAccessOf(proxy) != nil }

// AddrInUse reports whether err says that another socket holds the address.
func AddrInUse(err error) bool { return wgAddrInUse(err) }

// RefreshWireGuard does what the retry timer does.
func RefreshWireGuard() { refreshWireGuard() }

// WireGuardSession returns the running session that proxy uses, or why it has none.
func WireGuardSession(proxy C.Proxy) (*WireGuard, error) {
	p := wireGuardPeerAccessOf(proxy)
	if p == nil {
		return nil, errors.New("no peer access")
	}
	return p.running()
}

// WireGuardSessionOf returns the running session that proxy uses, or nil.
func WireGuardSessionOf(proxy C.Proxy) *WireGuard {
	w, _ := WireGuardSession(proxy)
	return w
}

func TestWireGuardLegacyDeviceConfig(t *testing.T) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peer, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	key := peer.PublicKey().Bytes()
	opt := WireGuardOption{Name: "wg", Ip: "10.8.0.1", Ipv6: "fd00:8::1", PrivateKey: base64.StdEncoding.EncodeToString(k.Bytes()), PersistentKeepalive: 7,
		WireGuardPeerOption: WireGuardPeerOption{Server: "127.0.0.1", Port: 51900, PublicKey: base64.StdEncoding.EncodeToString(key), AllowedIPs: []string{"10.8.0.2/32"}},
	}
	keys := "private_key=" + hex.EncodeToString(k.Bytes()) + "\npublic_key=" + hex.EncodeToString(key) + "\n"
	for _, tc := range []struct {
		ip, ipv6, server, endpoint, routes string
		list                               bool
	}{
		{"10.8.0.1", "fd00:8::1", "127.0.0.1", "127.0.0.1:51900", "allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n", false},
		{"10.8.0.1", "fd00:8::1", "127.0.0.1", "127.0.0.1:51900", "allowed_ip=10.8.0.2/32\n", true},
		{"", "::ffff:10.8.0.1", "::ffff:127.0.0.1", "[::ffff:127.0.0.1]:51900", "allowed_ip=::/0\n", false},
	} {
		opt := opt
		opt.Ip, opt.Ipv6, opt.Server = tc.ip, tc.ipv6, tc.server
		if tc.list {
			opt.Peers = []WireGuardPeerOption{opt.WireGuardPeerOption}
		}
		w, err := NewWireGuard(opt)
		require.NoError(t, err)
		require.Nil(t, w.device)
		require.IsType(t, (*wireguard.ClientBind)(nil), w.deviceBind(context.Background()))
		w.serverAddrMap = make(map[M.Socksaddr]netip.AddrPort)
		got, err := w.genIpcConf(context.Background(), false)
		require.NoError(t, err)
		if got != keys+"endpoint="+tc.endpoint+"\n"+tc.routes+"persistent_keepalive_interval=7\n" {
			t.Fatalf("legacy WireGuard device configuration changed for endpoint %s", tc.endpoint)
		}
		require.NoError(t, w.Close())
	}
}

func TestWireGuardKeepalive(t *testing.T) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	key := base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	base := WireGuardOption{Name: "wg", Ip: "10.8.0.1", PrivateKey: base64.StdEncoding.EncodeToString(k.Bytes()), ListenPort: 51900}
	dialed := WireGuardPeerOption{Server: "127.0.0.1", Port: 51901, PublicKey: key, AllowedIPs: []string{"10.8.0.2/32"}}
	passive := WireGuardPeerOption{PublicKey: base64.StdEncoding.EncodeToString(other.PublicKey().Bytes()), AllowedIPs: []string{"10.8.0.3/32"}}
	endpoint := netip.MustParseAddrPort("127.0.0.1:51901")
	for _, tc := range []struct {
		name            string
		top             any // the top-level option as it was decoded
		api             int // PersistentKeepalive
		peer            any // the option of the dialed peer
		dialed, passive int
	}{
		{"default", nil, 0, nil, 25, 0},
		{"top level", 15, 15, nil, 15, 15},
		{"top level off", 0, 0, nil, 0, 0},
		{"top level as text", "15", 15, nil, 15, 15},
		{"PersistentKeepalive only", nil, 7, nil, 7, 7},
		{"Keepalive only", 7, 0, nil, 7, 7},
		{"peer", 15, 15, 3, 3, 15},
		{"peer as text", nil, 0, "3", 3, 0},
		{"peer off", nil, 0, 0, 0, 0},
		{"peer highest", nil, 0, 65535, 65535, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := base
			opt.Keepalive, opt.PersistentKeepalive = tc.top, tc.api
			peer := dialed
			peer.Keepalive = tc.peer
			opt.Peers = []WireGuardPeerOption{peer, passive}
			w, err := NewWireGuard(opt)
			require.NoError(t, err)
			require.Equal(t, tc.dialed, w.keepalive(w.option.Peers[0], endpoint))
			require.Equal(t, tc.passive, w.keepalive(w.option.Peers[1], netip.AddrPort{}))
			require.Zero(t, w.keepalive(w.option.Peers[0], netip.AddrPort{}), "an endpoint that is not resolved yet")
			require.Equal(t, tc.passive, w.option.PersistentKeepalive)
			require.Nil(t, w.option.Keepalive)
			if tc.peer != nil {
				return
			}
			// The form with one peer at the top level gives the same.
			opt = base
			opt.WireGuardPeerOption = dialed
			opt.Keepalive, opt.PersistentKeepalive = tc.top, tc.api
			single, err := NewWireGuard(opt)
			require.NoError(t, err)
			require.Equal(t, tc.dialed, single.keepalive(single.option.Peers[0], endpoint))
			require.Equal(t, tc.passive, single.option.PersistentKeepalive)
		})
	}
	// A number that does not fit a 32-bit int is out of range on every platform.
	for _, wide := range []int64{1 << 32, 1<<32 + 1, -(1 << 32)} {
		opt := base
		opt.WireGuardPeerOption = dialed
		opt.Keepalive = wide
		_, err = NewWireGuard(opt)
		require.ErrorContains(t, err, "between 0 and 65535")
		opt.Keepalive = nil
		peer := dialed
		peer.Keepalive = wide
		opt.Peers = []WireGuardPeerOption{peer}
		_, err = NewWireGuard(opt)
		require.ErrorContains(t, err, "peer 0: persistent-keepalive must be between 0 and 65535")
	}
	// The device takes 0 to 65535. That holds for a top-level value that no peer uses too.
	for _, interval := range []int{-1, 65536} {
		opt := base
		opt.WireGuardPeerOption = dialed
		opt.PersistentKeepalive = interval
		_, err = NewWireGuard(opt)
		require.ErrorContains(t, err, "between 0 and 65535")
		peer := dialed
		peer.Keepalive = 0
		opt.Peers = []WireGuardPeerOption{peer}
		_, err = NewWireGuard(opt)
		require.ErrorContains(t, err, "between 0 and 65535")
		opt.PersistentKeepalive, peer.Keepalive = 0, interval
		opt.Peers = []WireGuardPeerOption{peer}
		_, err = NewWireGuard(opt)
		require.ErrorContains(t, err, "peer 0: persistent-keepalive must be between 0 and 65535")
	}
	// Without peer access only the proxy's own value counts, as before.
	opt := base
	opt.ListenPort, opt.PersistentKeepalive = 0, 7
	peer := dialed
	peer.Keepalive = "not a number"
	opt.Peers = []WireGuardPeerOption{peer}
	w, err := NewWireGuard(opt)
	require.NoError(t, err)
	require.Equal(t, 7, w.keepalive(w.option.Peers[0], endpoint))
	// With peer access it has to be a number.
	opt.ListenPort, opt.Peers = 51900, []WireGuardPeerOption{peer} // NewWireGuard has rewritten the key
	_, err = NewWireGuard(opt)
	require.ErrorContains(t, err, "peer 0: cannot parse 'persistent-keepalive' as int")
}

// testListener is a listening proxy whose socket is opened by listen.
type testListener struct {
	C.Proxy
	adapter C.ProxyAdapter
	read    func() // called when a sync reads the proxy
}

func (p *testListener) Adapter() C.ProxyAdapter {
	if p.read != nil {
		p.read()
	}
	return p.adapter
}

type testListen struct {
	C.Dialer
	listen func() error
}

func (d testListen) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, d.listen()
}

func newTestListener(t *testing.T, name string, listen func() error) *testListener {
	key := func() string {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		return base64.StdEncoding.EncodeToString(k.Bytes())
	}
	adapter, err := NewWireGuardProxy(WireGuardOption{BasicOption: BasicOption{DialerForAPI: testListen{listen: listen}, TunnelForAPI: struct{ C.Tunnel }{}},
		Name: name, Ip: "10.8.0.1", PrivateKey: key(), ListenPort: 51900, Workers: 1,
		WireGuardPeerOption: WireGuardPeerOption{PublicKey: key(), AllowedIPs: []string{"10.8.0.2/32"}}})
	require.NoError(t, err)
	return &testListener{adapter: adapter}
}

// Each session that is not up has its own wait, which doubles. A session that
// fails for the first time waits one second, however long another one has failed.
func TestWireGuardRetryWait(t *testing.T) {
	OpenWireGuard(func() {})
	defer func() { OpenWireGuard(nil); SyncWireGuard(nil, true) }()
	busy := func() error { return syscall.EADDRINUSE }
	first, second := newTestListener(t, "first", busy), newTestListener(t, "second", busy)
	waits := func(proxies ...C.Proxy) (waits []time.Duration) {
		SyncWireGuard(proxies, true)
		wgSessions.Lock()
		defer wgSessions.Unlock()
		for _, s := range wgSessions.running {
			waits = append(waits, s.retryWait)
		}
		return waits
	}
	require.Equal(t, []time.Duration{time.Second}, waits(first))
	require.Equal(t, []time.Duration{2 * time.Second}, waits(first))
	require.Equal(t, []time.Duration{4 * time.Second}, waits(first))
	require.Equal(t, []time.Duration{8 * time.Second, time.Second}, waits(first, second))
	require.Equal(t, []time.Duration{2 * time.Second}, waits(second))
	for i := 0; i < 6; i++ {
		waits(second)
	}
	require.Equal(t, []time.Duration{wgRetryMax}, waits(second))
	require.Empty(t, waits())
	require.Nil(t, wgSessions.running, "the closed sessions are not kept")
}

// The wait of a session counts from its own failure, not from the end of the
// sync that tried it.
func TestWireGuardRetryTime(t *testing.T) {
	due := make(chan time.Time, 1)
	OpenWireGuard(func() { due <- time.Now() })
	defer func() { OpenWireGuard(nil); SyncWireGuard(nil, true) }()
	first := newTestListener(t, "first", func() error { return syscall.EADDRINUSE })
	second := newTestListener(t, "second", func() error { time.Sleep(1200 * time.Millisecond); return syscall.EADDRINUSE })
	SyncWireGuard([]C.Proxy{first, second}, true)
	synced := time.Now()
	select {
	case at := <-due:
		require.Less(t, at.Sub(synced), 500*time.Millisecond, "the first session was due during the sync")
	case <-time.After(3 * time.Second):
		t.Fatal("no retry was asked for")
	}
}

// A sync that has not started its sessions when CloseWireGuard runs starts none.
func TestWireGuardCloseDuringSync(t *testing.T) {
	OpenWireGuard(nil)
	defer OpenWireGuard(nil)
	var binds atomic.Int32
	p := newTestListener(t, "wg", func() error { binds.Add(1); return syscall.EADDRINUSE })
	reading, resume, synced, closed := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	p.read = func() { once.Do(func() { close(reading); <-resume }) }
	go func() { SyncWireGuard([]C.Proxy{p}, true); close(synced) }()
	<-reading
	go func() { CloseWireGuard(); close(closed) }()
	require.Eventually(t, func() bool {
		wgSessions.Lock()
		defer wgSessions.Unlock()
		return wgSessions.closed
	}, 3*time.Second, time.Millisecond)
	close(resume)
	<-synced
	<-closed
	require.Zero(t, binds.Load(), "a session started after CloseWireGuard")
	SyncWireGuard([]C.Proxy{p}, true)
	require.Zero(t, binds.Load(), "a session started before OpenWireGuard")
	OpenWireGuard(nil)
	SyncWireGuard([]C.Proxy{p}, true)
	require.NotZero(t, binds.Load())
	SyncWireGuard(nil, true)
}

// A CloseWireGuard that an OpenWireGuard has overtaken closes nothing: the
// sessions belong to the sync that follows the OpenWireGuard.
func TestWireGuardCloseOvertaken(t *testing.T) {
	OpenWireGuard(nil)
	defer func() { OpenWireGuard(nil); SyncWireGuard(nil, true) }()
	p := newTestListener(t, "wg", func() error { return syscall.EADDRINUSE })
	SyncWireGuard([]C.Proxy{p}, true)
	sessions := func() int {
		wgSessions.Lock()
		defer wgSessions.Unlock()
		return len(wgSessions.running)
	}
	require.Equal(t, 1, sessions())

	wgSessions.syncing.Lock() // as while a sync runs
	closed := make(chan struct{})
	go func() { CloseWireGuard(); close(closed) }()
	require.Eventually(t, func() bool {
		wgSessions.Lock()
		defer wgSessions.Unlock()
		return wgSessions.closed
	}, 3*time.Second, time.Millisecond)
	OpenWireGuard(nil)
	wgSessions.syncing.Unlock()
	<-closed
	require.Equal(t, 1, sessions())

	// One that nothing overtakes closes them.
	CloseWireGuard()
	require.Zero(t, sessions())
}

type testEndpointLookup struct {
	resolver.Resolver
}

func (testEndpointLookup) Invalid() bool { return true }

func (testEndpointLookup) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}

func (r testEndpointLookup) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}

// testDevice refuses the updates while refuse is set.
type testDevice struct {
	wireguardGoDevice
	refuse  bool
	updates []string
}

func (d *testDevice) Close() {}

func (d *testDevice) IpcSet(conf string) error {
	if d.refuse {
		return errors.New("refused")
	}
	d.updates = append(d.updates, conf)
	return nil
}

// An endpoint that the device did not take is given to it again.
func TestWireGuardEndpointUpdateRefused(t *testing.T) {
	prev := resolver.ProxyServerHostResolver
	resolver.ProxyServerHostResolver = testEndpointLookup{}
	defer func() { resolver.ProxyServerHostResolver = prev }()
	key := func() string {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		return base64.StdEncoding.EncodeToString(k.Bytes())
	}
	w, err := NewWireGuard(WireGuardOption{Name: "wg", Ip: "10.8.0.1", PrivateKey: key(), ListenPort: 51900, Peers: []WireGuardPeerOption{
		{Server: "first.invalid", Port: 51901, PublicKey: key(), AllowedIPs: []string{"10.8.0.2/32"}},
		{Server: "second.invalid", Port: 51902, PublicKey: key(), AllowedIPs: []string{"10.8.0.3/32"}},
	}})
	require.NoError(t, err)
	defer w.Close()
	device := &testDevice{refuse: true}
	w.device, w.serverAddrMap = device, make(map[M.Socksaddr]netip.AddrPort)
	w.initOk.Store(true)

	resolved, err := w.refreshEndpoints(context.Background())
	require.ErrorContains(t, err, "refused")
	require.False(t, resolved)
	require.Empty(t, w.serverAddrMap)

	device.refuse = false
	resolved, err = w.refreshEndpoints(context.Background())
	require.NoError(t, err)
	require.True(t, resolved)
	require.Len(t, device.updates, 1)
	require.Contains(t, device.updates[0], "endpoint=192.0.2.1:51901\n")
	require.Contains(t, device.updates[0], "endpoint=192.0.2.1:51902\n")
	require.Equal(t, 2, strings.Count(device.updates[0], "persistent_keepalive_interval=25\n"))
}
