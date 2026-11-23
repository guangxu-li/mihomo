package tunnel_test

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/require"
)

// testGroup stands for a proxy group that has selected a proxy.
type testGroup struct {
	C.ProxyAdapter
	selected C.Proxy
}

func (g testGroup) Unwrap(*C.Metadata, bool) C.Proxy { return g.selected }

func TestInboundLocal(t *testing.T) {
	inboundLocal := tunnel.InboundLocal
	local := outbound.NewDirectWithOption(outbound.DirectOption{Name: "local"})
	direct, reject, drop := outbound.NewDirect(), outbound.NewReject(), outbound.NewRejectDrop()
	group := func(selected C.ProxyAdapter) C.ProxyAdapter {
		return testGroup{direct, adapter.NewProxy(selected)}
	}

	// Without an own address the rules decide.
	plain := &C.Metadata{}
	require.Equal(t, C.ProxyAdapter(direct), inboundLocal(plain, direct))
	require.Nil(t, inboundLocal(plain, nil))

	// With one, only a reject keeps the connection away from the inbound.
	own := &C.Metadata{InboundLocal: local}
	for _, selected := range []C.ProxyAdapter{nil, direct, group(direct), group(group(direct))} {
		require.Equal(t, C.ProxyAdapter(local), inboundLocal(own, selected))
	}
	for _, selected := range []C.ProxyAdapter{reject, drop, group(reject), group(group(drop))} {
		got := inboundLocal(own, selected)
		require.NotEqual(t, C.ProxyAdapter(local), got)
		require.Contains(t, []C.AdapterType{C.Reject, C.RejectDrop}, got.Type())
	}
}
