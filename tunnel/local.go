package tunnel

import (
	C "github.com/metacubex/mihomo/constant"
)

// inboundLocal returns the adapter for a connection whose rule result is
// selected. A connection to the own address of its inbound stays on this
// device: unless the rules reject it, the inbound delivers it locally.
func inboundLocal(metadata *C.Metadata, selected C.ProxyAdapter) C.ProxyAdapter {
	if metadata.InboundLocal == nil {
		return selected
	}
	// A group may select a reject adapter.
	for proxy := selected; proxy != nil; proxy = proxy.Unwrap(metadata, false) {
		if proxy.Type() == C.Reject || proxy.Type() == C.RejectDrop {
			return proxy
		}
	}
	return metadata.InboundLocal
}
