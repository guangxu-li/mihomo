package outbound_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/profile"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
)

// The tests share one cache file and a running tunnel. The cache file stays
// open until the process ends, so it lives in a home that no test removes.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "mihomo-test")
	if err != nil {
		panic(err)
	}
	C.SetHomeDir(home)
	cache := cachefile.Cache()
	tunnel.OnRunning()
	code := m.Run()
	if cache.DB != nil {
		_ = cache.Close()
	}
	_ = os.RemoveAll(home)
	os.Exit(code)
}

func testConfig(t *testing.T) {
	t.Helper()
	prev := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(prev) })
}

func TestWireGuardDocumentedExamples(t *testing.T) {
	testConfig(t)
	docs, err := os.ReadFile("../../docs/config.yaml")
	require.NoError(t, err)
	const start = "  # - name: wg-server"
	_, examples, found := strings.Cut(strings.ReplaceAll(string(docs), "\r\n", "\n"), start)
	require.True(t, found, "missing WireGuard examples")
	examples, _, _ = strings.Cut(start+examples, "\n\n")
	var config strings.Builder
	config.WriteString("proxies:\n")
	for _, line := range strings.Split(examples, "\n") {
		config.WriteString(strings.TrimPrefix(line, "  #"))
		config.WriteByte('\n')
	}
	server, phone := keys(t), keys(t)
	example := strings.NewReplacer("<server private key>", server.private, "<server public key>", server.public,
		"<phone private key>", phone.private, "<phone public key>", phone.public, "<laptop public key>", keys(t).public).Replace(config.String())
	cfg, err := executor.ParseWithBytes([]byte(example))
	require.NoError(t, err)
	for _, name := range []string{"wg-server", "wg-client"} {
		require.Contains(t, cfg.Proxies, name)
		require.True(t, outbound.HasWireGuardPeerAccess(cfg.Proxies[name]))
		require.Nil(t, outbound.WireGuardSessionOf(cfg.Proxies[name]), "parsing must not start a session")
	}
	checkPort(t, 51900, false)
}

func TestWireGuardConfigLifecycle(t *testing.T) {
	testConfig(t)
	base := []byte("mode: rule\nlog-level: silent\nprofile: {store-selected: false}\n")
	empty, err := executor.ParseWithBytes(base)
	require.NoError(t, err)
	t.Cleanup(func() { executor.ApplyConfig(empty, false) })
	port := testPort(t)
	node, peer := keys(t), keys(t)
	peers := []map[string]any{{"public-key": peer.public, "allowed-ips": []string{"10.8.0.2/32"}}}
	m := map[string]any{"name": "wg", "type": "wireguard", "listen-port": port, "ip": "10.8.0.1", "private-key": node.private, "peers": peers, "workers": 1}
	parse := func() *config.Config {
		data, err := yaml.Marshal(map[string]any{
			"proxies": []any{m}, "log-level": "silent", "profile": map[string]any{"store-selected": true},
			"proxy-groups": []map[string]any{{"name": "test-policy", "type": "select", "proxies": []string{"DIRECT", "REJECT"}}},
		})
		require.NoError(t, err)
		cfg, err := executor.ParseWithBytes(data)
		require.NoError(t, err)
		return cfg
	}
	first := parse()
	require.Nil(t, outbound.WireGuardSessionOf(first.Proxies["wg"]))
	checkPort(t, port, false)
	profile.StoreSelected.Store(true)
	cachefile.Cache().SetSelected("test-policy", "REJECT")
	withLoopbackSockets(t, func() error {
		if tunnel.Status() != tunnel.Running || tunnel.Proxies()["test-policy"].Adapter().(interface{ Now() string }).Now() != "REJECT" {
			return fmt.Errorf("WireGuard bound before rule processing and selector restoration")
		}
		return nil
	})
	executor.ApplyConfig(first, false)
	running := session(t, first.Proxies["wg"])
	checkPort(t, port, true)
	own := netip.MustParseAddr("10.8.0.1")
	echo, _ := loopbackEcho(t, own)
	client := makeWG(t, outbound.WireGuardOption{Name: "client", Ip: "10.8.0.2", PrivateKey: peer.private,
		WireGuardPeerOption: outbound.WireGuardPeerOption{PublicKey: node.public, Server: "127.0.0.1", Port: port}})
	c := dial(t, client, own, echo)
	defer c.Close()
	assertTCP(t, c)
	handshake := func(w *outbound.WireGuard) string {
		var fields []string
		for _, line := range strings.Split(peerState(t, w), "\n") {
			if strings.HasPrefix(line, "last_handshake_time_") {
				fields = append(fields, line)
			}
		}
		require.Len(t, fields, 2)
		require.NotEqual(t, "last_handshake_time_sec=0", fields[0])
		return strings.Join(fields, "\n")
	}
	done, since := running.TestDeviceDone(), handshake(running)

	// A reload with the same options keeps the session, for the old proxy too.
	for i := 0; i < 3; i++ {
		replacement := parse()
		executor.ApplyConfig(replacement, true)
		require.Same(t, running, session(t, replacement.Proxies["wg"]))
		require.Same(t, running, session(t, first.Proxies["wg"]))
		require.NoError(t, first.Proxies["wg"].Close())
		assertTCP(t, c)
		require.Equal(t, since, handshake(running))
		local := dial(t, first.Proxies["wg"], own, echo)
		assertTCP(t, local)
		_ = local.Close()
	}
	// Changed options replace it. The port is free in between.
	var last *config.Config
	for i := 0; i < 4; i++ {
		m["peers"] = append(peers, map[string]any{"public-key": keys(t).public, "allowed-ips": []string{"10.8.0.3/32"}})
		last = parse()
		executor.ApplyConfig(last, true)
		checkStopped(t, done)
		checkPort(t, port, true)
		done = session(t, last.Proxies["wg"]).TestDeviceDone()
	}
	_, err = first.Proxies["wg"].DialContext(context.Background(), metadata(own, echo))
	require.ErrorContains(t, err, "not running")
	_ = c.Close()
	_ = client.Close()
	newPort := testPort(t)
	m["listen-port"] = newPort
	moved := parse()
	executor.ApplyConfig(moved, false)
	checkStopped(t, done)
	checkPort(t, port, false)
	checkPort(t, newPort, true)
	done = session(t, moved.Proxies["wg"]).TestDeviceDone()

	executor.Shutdown()
	checkStopped(t, done)
	checkPort(t, newPort, false)
	outbound.RefreshWireGuard() // nothing starts after a shutdown
	checkPort(t, newPort, false)
	executor.ApplyConfig(empty, false)

	// A session that dials its peer keeps a stream that the peer opened.
	serverPort := testPort(t)
	server := makeWG(t, outbound.WireGuardOption{Name: "server", Ip: "10.8.0.1", PrivateKey: node.private,
		ListenPort: serverPort, WireGuardPeerOption: outbound.WireGuardPeerOption{PublicKey: peer.public, AllowedIPs: []string{"10.8.0.2/32"}}})
	require.NoError(t, server.Start())
	m = map[string]any{"name": "wg", "type": "wireguard", "accept-incoming": true, "ip": "10.8.0.2",
		"private-key": peer.private, "public-key": node.public, "server": "127.0.0.1", "port": serverPort, "workers": 1, "persistent-keepalive": 0}
	transport := &countedTransport{localTransport: localTransport{testPort(t)}}
	dialConfig := func() *config.Config {
		cfg, err := executor.ParseWithBytes(base)
		require.NoError(t, err)
		cfg.Proxies["wg"], err = adapter.ParseProxy(m, adapter.WithTunnelForAPI(tunnel.Tunnel), adapter.WithDialerForAPI(transport))
		require.NoError(t, err)
		return cfg
	}
	cfg := dialConfig()
	require.Zero(t, transport.dials.Load())
	executor.ApplyConfig(cfg, false)
	dialing := session(t, cfg.Proxies["wg"])
	requirePeerField(t, dialing, "persistent_keepalive_interval=0\n")
	c = dial(t, cfg.Proxies["wg"], own, echo)
	assertTCP(t, c)
	_ = c.Close()
	c = dial(t, server, netip.MustParseAddr("10.8.0.2"), echo)
	defer c.Close()
	assertTCP(t, c)
	done, since = dialing.TestDeviceDone(), handshake(dialing)
	delete(m, "accept-incoming")
	m["allow-peer-access"] = true // the other name of the same option
	cfg = dialConfig()
	executor.ApplyConfig(cfg, true)
	require.Same(t, dialing, session(t, cfg.Proxies["wg"]))
	assertTCP(t, c)
	require.Equal(t, since, handshake(dialing))
	require.EqualValues(t, 1, transport.dials.Load())
	executor.ApplyConfig(empty, false)
	checkStopped(t, done)
}

// A proxy provider must not bring a proxy with peer access.
func TestWireGuardProviderRejected(t *testing.T) {
	testConfig(t)
	t.Cleanup(func() { executor.ApplyConfig(blankConfig(t), false) })
	const refused = "not supported in a proxy provider"
	port := testPort(t)
	listener := listenerOptions(t, port)
	plain := map[string]any{"name": "plain", "type": "direct"}
	parse := func(provider map[string]any) (*config.Config, error) {
		data, err := yaml.Marshal(map[string]any{
			"log-level": "silent", "profile": map[string]any{"store-selected": false},
			"proxy-providers": map[string]any{"test": provider},
		})
		require.NoError(t, err)
		return executor.ParseWithBytes(data)
	}

	// An inline provider is a part of the config, so the config is rejected.
	_, err := parse(map[string]any{"type": "inline", "payload": []any{listener}})
	require.ErrorContains(t, err, refused)

	// A provider that finds such a proxy when it loads has no proxies.
	write := func(rows ...map[string]any) {
		data, err := yaml.Marshal(map[string]any{"proxies": rows})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(C.Path.HomeDir(), "provider.yaml"), data, 0o600))
	}
	write(listener)
	cfg, err := parse(map[string]any{"type": "file", "path": "./provider.yaml"})
	require.NoError(t, err)
	executor.ApplyConfig(cfg, false)
	set := cfg.Providers["test"]
	require.Empty(t, set.Proxies())
	checkPort(t, port, false)

	// A WireGuard proxy without the new options is accepted, as before.
	dialed := map[string]any{"name": "dialed", "type": "wireguard", "ip": "10.8.0.2", "private-key": keys(t).private,
		"public-key": keys(t).public, "server": "127.0.0.1", "port": testPort(t)}
	write(plain, dialed)
	require.NoError(t, set.Update())
	require.Len(t, set.Proxies(), 2)
	require.False(t, outbound.HasWireGuardPeerAccess(set.Proxies()[1]))

	// An update that brings one is rejected. The earlier proxies stay.
	kept := slices.Clone(set.Proxies())
	write(plain, listener)
	require.ErrorContains(t, set.Update(), refused)
	require.Len(t, set.Proxies(), 2)
	require.Same(t, kept[0], set.Proxies()[0])
	require.Same(t, kept[1], set.Proxies()[1])
	checkPort(t, port, false)
}

// A session that cannot start is tried again without another ApplyConfig.
func TestWireGuardRetryAfterPortRelease(t *testing.T) {
	testConfig(t)
	t.Cleanup(func() { executor.ApplyConfig(blankConfig(t), false) })
	port := testPort(t)
	busy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	require.NoError(t, err)
	defer busy.Close()
	cfg := blankConfig(t)
	cfg.Proxies["wg"] = parseListener(t, listenerOptions(t, port))
	executor.ApplyConfig(cfg, false)
	require.Nil(t, outbound.WireGuardSessionOf(cfg.Proxies["wg"]))
	require.NoError(t, busy.Close())
	require.Eventually(t, func() bool { return outbound.WireGuardSessionOf(cfg.Proxies["wg"]) != nil }, 5*time.Second, 10*time.Millisecond)
	checkPort(t, port, true)
}

// blockedListen holds the opening of a listening socket until release is closed.
type blockedListen struct {
	localTransport
	entered, release chan struct{}
}

func (d *blockedListen) ListenPacket(ctx context.Context, network, address string, dst netip.AddrPort) (net.PacketConn, error) {
	if network == "udp4" {
		close(d.entered)
		select {
		case <-d.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return d.localTransport.ListenPacket(ctx, network, address, dst)
}

// A Shutdown does not wait for a session that an ApplyConfig is starting.
func TestWireGuardShutdownDuringStart(t *testing.T) {
	testConfig(t)
	t.Cleanup(func() { executor.ApplyConfig(blankConfig(t), false) })
	port := testPort(t)
	stuck := &blockedListen{entered: make(chan struct{}), release: make(chan struct{})}
	cfg := blankConfig(t)
	var err error
	cfg.Proxies["wg"], err = adapter.ParseProxy(listenerOptions(t, port), adapter.WithTunnelForAPI(tunnel.Tunnel), adapter.WithDialerForAPI(stuck))
	require.NoError(t, err)
	applied := make(chan struct{})
	go func() { executor.ApplyConfig(cfg, false); close(applied) }()
	waitFor(t, stuck.entered)
	stopped := make(chan struct{})
	go func() { executor.Shutdown(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown waited for the start")
	}
	waitFor(t, applied)
	checkPort(t, port, false)
}

// hookedProvider reports when the executor initializes it.
type hookedProvider struct {
	P.ProxyProvider
	initial func()
}

func (p *hookedProvider) Initial() error {
	p.initial()
	return p.ProxyProvider.Initial()
}

func blankConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := executor.ParseWithBytes([]byte("mode: rule\nlog-level: silent\nprofile: {store-selected: false}\n"))
	require.NoError(t, err)
	return cfg
}

// A Shutdown during an ApplyConfig wins: that ApplyConfig starts no session.
func TestWireGuardShutdownDuringApply(t *testing.T) {
	testConfig(t)
	t.Cleanup(func() { executor.ApplyConfig(blankConfig(t), false) })
	port := testPort(t)
	listener := listenerOptions(t, port)
	// The ApplyConfig waits where it loads its providers.
	held, err := executor.ParseWithBytes([]byte("log-level: silent\nprofile: {store-selected: false}\nproxy-providers: {test: {type: inline, payload: [{name: plain, type: direct}]}}\n"))
	require.NoError(t, err)
	initial, resume, applied := make(chan struct{}), make(chan struct{}), make(chan struct{})
	held.Providers["test"] = &hookedProvider{ProxyProvider: held.Providers["test"], initial: func() { close(initial); <-resume }}
	held.Proxies["wg"] = parseListener(t, listener)
	go func() { executor.ApplyConfig(held, false); close(applied) }()
	waitFor(t, initial)
	executor.Shutdown()
	close(resume)
	waitFor(t, applied)
	require.Nil(t, outbound.WireGuardSessionOf(held.Proxies["wg"]))
	checkPort(t, port, false)

	// An ApplyConfig that begins after the Shutdown starts it.
	cfg := blankConfig(t)
	cfg.Proxies["wg"] = parseListener(t, listener)
	executor.ApplyConfig(cfg, false)
	require.NotNil(t, outbound.WireGuardSessionOf(cfg.Proxies["wg"]))
	checkPort(t, port, true)
}
