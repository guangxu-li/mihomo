package resolver

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/trie"
	"github.com/stretchr/testify/require"
)

func buildTestHostsTrie(t *testing.T, ip string) *trie.DomainTrie[HostValue] {
	t.Helper()
	tree := trie.New[HostValue]()
	target, err := NewHostValue([]string{ip})
	require.NoError(t, err)
	alias, err := NewHostValue([]string{"target.example"})
	require.NoError(t, err)
	require.NoError(t, tree.Insert("target.example", target))
	require.NoError(t, tree.Insert("alias.example", alias))
	return tree
}

func TestHostsSearchSnapshotAndConcurrentStore(t *testing.T) {
	oldDisable := DisableSystemHosts
	oldUse := UseSystemHosts.Swap(false)
	DisableSystemHosts = false
	t.Cleanup(func() {
		UseSystemHosts.Store(oldUse)
		DisableSystemHosts = oldDisable
	})

	h := NewHosts(trie.New[HostValue]())
	_, ok := h.Search("missing.example", false)
	require.False(t, ok)

	t1 := buildTestHostsTrie(t, "10.8.0.1")
	t2 := buildTestHostsTrie(t, "10.8.0.2")
	h.Store(t1)

	got, ok := h.Search("alias.example", false)
	require.True(t, ok)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.8.0.1")}, got.IPs)

	gotDomain, ok := h.Search("alias.example", true)
	require.True(t, ok)
	require.True(t, gotDomain.IsDomain)
	require.Equal(t, "target.example", gotDomain.Domain)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if v, ok := h.Search("alias.example", false); ok {
					ip := v.IPs[0]
					if ip != netip.MustParseAddr("10.8.0.1") && ip != netip.MustParseAddr("10.8.0.2") {
						t.Errorf("unexpected IP from concurrent Search: %s", ip)
						return
					}
				}
				_, _ = h.Search("absent.example", false)
			}
		}()
	}

	for i := 0; i < 2000; i++ {
		if i%2 == 0 {
			h.Store(t2)
			UseSystemHosts.Store(true)
		} else {
			h.Store(t1)
			UseSystemHosts.Store(false)
		}
	}
	close(stop)
	wg.Wait()
}
