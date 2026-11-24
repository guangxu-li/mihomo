package executor

import (
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

var wgRefresh = make(chan struct{}, 1)

func init() {
	go func() {
		for range wgRefresh {
			mux.Lock()
			syncWireGuard(false)
			mux.Unlock()
		}
	}()
}

// syncWireGuard runs the WireGuard peer-access sessions for the proxies of the
// config. The caller holds mux, so that no config is applied while the
// sessions start. applied tells that the caller has just applied a config.
func syncWireGuard(applied bool) {
	var proxies []C.Proxy
	for _, proxy := range tunnel.Proxies() {
		proxies = append(proxies, proxy)
	}
	outbound.SyncWireGuard(proxies, applied)
}

// refreshWireGuard asks for a sync with the proxies that are published by
// then. It does not wait: the sync that it asks for may be the one that is due.
func refreshWireGuard() {
	select {
	case wgRefresh <- struct{}{}:
	default: // the sync that is due reads the newest proxies
	}
}
