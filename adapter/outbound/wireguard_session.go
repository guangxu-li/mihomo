package outbound

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"golang.org/x/exp/slices"
)

// A proxy with peer access has to run before anything uses it, and it has to
// keep running when a reload builds a new proxy with the same options. So the
// proxy does not own a WireGuard device. SyncWireGuard runs one session for
// each set of options among the published proxies, and every proxy uses the
// session that has its options.

// wireGuardPeerAccess is the adapter of a WireGuard proxy with peer access.
type wireGuardPeerAccess struct {
	*WireGuard // describes the proxy and is never started

	configured WireGuardOption           // what a session for the proxy is made from
	session    atomic.Pointer[wgSession] // the session that was used last
}

// NewWireGuardProxy returns the adapter of a WireGuard proxy in a config. For
// a proxy with peer access, SyncWireGuard runs its session.
func NewWireGuardProxy(option WireGuardOption) (ProxyAdapter, error) {
	w, err := NewWireGuard(option)
	if err != nil {
		return nil, err
	}
	if !w.option.AllowPeerAccess {
		return w, nil
	}
	if option.ListenPort != 0 && option.DialerProxy != "" {
		log.Warnln("[WG](%s) ignoring dialer-proxy with listen-port", option.Name)
	}
	w.runCancel()
	return &wireGuardPeerAccess{WireGuard: w, configured: option}, nil
}

// running returns the session that serves the proxy.
func (p *wireGuardPeerAccess) running() (*WireGuard, error) {
	s := p.session.Load()
	if s == nil || s.runCtx.Err() != nil { // a closed session never comes back
		wgSessions.Lock()
		i := slices.IndexFunc(wgSessions.running, func(s *wgSession) bool { return s.serves(p) })
		if i < 0 {
			wgSessions.Unlock()
			return nil, errors.New("WireGuard peer access is not running")
		}
		s = wgSessions.running[i]
		wgSessions.Unlock()
		p.session.Store(s)
	}
	if !s.initOk.Load() {
		if err := s.startErr.Load(); err != nil {
			return nil, fmt.Errorf("WireGuard peer access is not running: %w", *err)
		}
		return nil, errors.New("WireGuard peer access is starting")
	}
	return s.WireGuard, nil
}

func (p *wireGuardPeerAccess) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	w, err := p.running()
	if err != nil {
		return nil, err
	}
	return w.DialContext(ctx, metadata)
}

func (p *wireGuardPeerAccess) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	w, err := p.running()
	if err != nil {
		return nil, err
	}
	return w.ListenPacketContext(ctx, metadata)
}

func (p *wireGuardPeerAccess) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	w, err := p.running()
	if err != nil {
		return err
	}
	return w.ResolveUDP(ctx, metadata)
}

// Close does nothing: the session belongs to SyncWireGuard.
func (p *wireGuardPeerAccess) Close() error {
	return nil
}

// wgSession is a running WireGuard device with peer access.
type wgSession struct {
	*WireGuard

	first     *wireGuardPeerAccess // the proxy that the session was made for
	startErr  atomic.Pointer[error]
	retryWait time.Duration // doubles up to wgRetryMax while the session is not up
}

// serves reports whether p uses the session: p has the session's options.
func (s *wgSession) serves(p *wireGuardPeerAccess) bool {
	return s.first == p || sameWireGuardOptions(s.option, p.option)
}

var wgSessions struct {
	sync.Mutex
	running []*wgSession

	closed  bool     // CloseWireGuard: no session runs until OpenWireGuard
	refresh func()   // asks for a SyncWireGuard with the proxies that are published by then
	global  wgEgress // the global interface-name and routing-mark of the applied config

	syncing   sync.Mutex         // held while sessions start and close
	interrupt context.CancelFunc // ends the waits of the SyncWireGuard that is in progress
	retry     *time.Timer        // refreshes while a session is not up
}

const wgRetryMax = 30 * time.Second

// SyncWireGuard makes the running peer-access sessions match published, which
// holds every proxy that is in use. It closes the sessions that no proxy needs
// any more, then starts the missing ones. A session whose options stay the
// same keeps running with its sockets, handshakes and connections.
//
// The caller reads published and calls SyncWireGuard under one lock, so that
// the last call applies the newest proxies. After CloseWireGuard it starts no
// session until OpenWireGuard.
//
// applied tells that the caller has applied a config since its last call. Only
// then are the global interface-name and routing-mark read again: parsing a
// config changes them for a moment, also when that config is never applied.
//
// A session that is not up is tried again in every call, and in a call that a
// timer asks for: 1 s after it failed, then twice as long each time, up to
// wgRetryMax.
func SyncWireGuard(published []C.Proxy, applied bool) {
	wgSessions.syncing.Lock()
	defer wgSessions.syncing.Unlock()

	var wanted []*wireGuardPeerAccess
	for _, proxy := range published {
		if p := wireGuardPeerAccessOf(proxy); p != nil && !slices.ContainsFunc(wanted, func(other *wireGuardPeerAccess) bool {
			return other == p || sameWireGuardOptions(other.option, p.option)
		}) {
			wanted = append(wanted, p)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var closing []*wgSession
	var running []*wgSession
	wgSessions.Lock()
	wgSessions.interrupt = cancel
	if wgSessions.closed {
		wanted = nil
	}
	if wgSessions.retry != nil {
		wgSessions.retry.Stop()
		wgSessions.retry = nil
	}
	if applied {
		wgSessions.global = wgGlobalEgress()
	}
	global := wgSessions.global
	for _, s := range wgSessions.running {
		// A socket keeps what it was opened with, so a changed routing mark needs a new session.
		i := slices.IndexFunc(wanted, func(p *wireGuardPeerAccess) bool { return s.serves(p) && *s.egress == wgEgressOf(p.option, global) })
		if i < 0 {
			closing = append(closing, s)
			continue
		}
		running = append(running, s)
		wanted = slices.Delete(wanted, i, i+1)
	}
	wgSessions.running = running
	wgSessions.Unlock()

	// A session releases its listen-port before its successor binds it.
	for _, s := range closing {
		_ = s.Close()
	}
	for _, p := range wanted {
		w, err := NewWireGuard(p.configured)
		if err != nil { // NewWireGuardProxy accepted the same options
			log.Errorln("[WG](%s) start: %s", p.configured.Name, err)
			continue
		}
		egress := wgEgressOf(w.option, global)
		w.egress = &egress
		running = append(running, &wgSession{WireGuard: w, first: p})
	}
	wgSessions.Lock()
	wgSessions.running = running
	wgSessions.Unlock()

	var retry time.Time // the earliest one of the sessions that are not up
	for _, s := range running {
		if s.up(ctx) {
			s.retryWait = 0
			continue
		}
		// The name of an endpoint may not resolve yet, or another program may still hold the port.
		if s.retryWait *= 2; s.retryWait == 0 {
			s.retryWait = time.Second
		} else if s.retryWait > wgRetryMax {
			s.retryWait = wgRetryMax
		}
		if due := time.Now().Add(s.retryWait); retry.IsZero() || due.Before(retry) {
			retry = due
		}
	}
	wgSessions.Lock()
	defer wgSessions.Unlock()
	wgSessions.interrupt = nil
	if !retry.IsZero() && !wgSessions.closed {
		wgSessions.retry = time.AfterFunc(time.Until(retry), refreshWireGuard)
	}
}

// OpenWireGuard lets SyncWireGuard run sessions again after a CloseWireGuard.
// refresh asks the caller for a SyncWireGuard with the proxies that are
// published by then. It must not wait for that call.
func OpenWireGuard(refresh func()) {
	wgSessions.Lock()
	defer wgSessions.Unlock()
	wgSessions.closed, wgSessions.refresh = false, refresh
}

// CloseWireGuard closes the sessions. It does not wait for a session that a
// SyncWireGuard is starting, and none starts before the next OpenWireGuard.
// An OpenWireGuard that comes while it waits takes over: the sessions are
// then left to the SyncWireGuard that follows it.
func CloseWireGuard() {
	wgSessions.Lock()
	wgSessions.closed = true
	if wgSessions.interrupt != nil {
		wgSessions.interrupt()
	}
	if wgSessions.retry != nil {
		wgSessions.retry.Stop()
	}
	wgSessions.Unlock()

	wgSessions.syncing.Lock()
	defer wgSessions.syncing.Unlock()
	var closing []*wgSession
	wgSessions.Lock()
	if wgSessions.closed {
		closing, wgSessions.running = wgSessions.running, nil
	}
	wgSessions.Unlock()
	for _, s := range closing {
		_ = s.Close()
	}
}

// refreshWireGuard asks for a new SyncWireGuard. A timer calls it while a
// session is not up.
func refreshWireGuard() {
	wgSessions.Lock()
	refresh := wgSessions.refresh
	wgSessions.Unlock()
	if refresh != nil {
		refresh()
	}
}

// up starts the session, then resolves the endpoint names that have no
// address yet. It reports whether nothing is left to try again.
func (s *wgSession) up(ctx context.Context) bool {
	start, cancel := context.WithTimeout(ctx, C.DefaultTCPTimeout)
	defer cancel()
	err := s.init0(start)
	resolved := false
	if err == nil {
		resolved, err = s.refreshEndpoints(start)
	}
	if ctx.Err() != nil {
		return false // interrupted
	}
	if err != nil && s.option.ListenPort != 0 && wgAddrInUse(err) {
		// Two proxies with one listen-port is the usual cause, so name the other one.
		wgSessions.Lock()
		for _, holder := range wgSessions.running {
			if holder != s && holder.option.ListenPort == s.option.ListenPort && holder.initOk.Load() {
				err = fmt.Errorf("%w (listen-port held by %s)", err, holder.Name())
				break
			}
		}
		wgSessions.Unlock()
	}
	last := s.startErr.Swap(nil)
	if err != nil {
		if last == nil || (*last).Error() != err.Error() {
			log.Errorln("[WG](%s) start: %s", s.Name(), err)
		}
		s.startErr.Store(&err)
		return s.initErr != nil // the device keeps this error: another try gives the same
	}
	return resolved // listenEndpoint has logged the reason
}

// wireGuardPeerAccessOf returns the peer-access adapter of proxy, or nil.
func wireGuardPeerAccessOf(proxy C.Proxy) *wireGuardPeerAccess {
	adapter := proxy.Adapter()
	for {
		switch a := adapter.(type) {
		case *autoCloseProxyAdapter:
			adapter = a.ProxyAdapter
		case *SingMux:
			adapter = a.ProxyAdapter
		case *wireGuardPeerAccess:
			return a
		default:
			return nil
		}
	}
}

// sameWireGuardOptions reports whether two proxies can use one session. The
// options are in the form that NewWireGuard gives them.
func sameWireGuardOptions(a, b WireGuardOption) bool {
	if !sameAPIValue(a.DialerForAPI, b.DialerForAPI) || !sameAPIValue(a.TunnelForAPI, b.TunnelForAPI) {
		return false
	}
	a.DialerForAPI, b.DialerForAPI = nil, nil
	a.TunnelForAPI, b.TunnelForAPI = nil, nil
	return reflect.DeepEqual(a, b)
}

// sameAPIValue reports whether a and b are one dialer or tunnel of the Go API.
// A pointer is itself. A value that cannot be compared counts by its content
// as reflect.DeepEqual sees it, so one with a func field is never the same:
// pass a pointer for it.
func sameAPIValue(a, b any) bool {
	if reflect.ValueOf(a).Comparable() && reflect.ValueOf(b).Comparable() {
		return a == b
	}
	return reflect.DeepEqual(a, b)
}

// wgEgress is what decides how the sockets of a session leave this device.
type wgEgress struct {
	mark  int
	iface string
}

// wgGlobalEgress returns the global routing-mark and interface-name of now.
func wgGlobalEgress() wgEgress {
	return wgEgress{int(dialer.DefaultRoutingMark.Load()), dialer.DefaultInterface.Load()}
}

// wgEgressOf returns the egress that a session with option starts with under
// the global settings. A proxy option wins over them, as for every outbound.
func wgEgressOf(option WireGuardOption, global wgEgress) wgEgress {
	egress := wgEgress{option.RoutingMark, option.Interface}
	if egress.mark == 0 {
		egress.mark = global.mark
	}
	if option.ListenPort != 0 {
		egress.iface = "" // the listening socket chooses the interface for each datagram
	} else if egress.iface == "" {
		egress.iface = global.iface
	}
	return egress
}
