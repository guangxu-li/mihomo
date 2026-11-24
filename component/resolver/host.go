package resolver

import (
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	_ "unsafe"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/resolver/hosts"
	"github.com/metacubex/mihomo/component/trie"
	"github.com/metacubex/randv2"
)

var (
	DisableSystemHosts, _ = strconv.ParseBool(os.Getenv("DISABLE_SYSTEM_HOSTS"))
	UseSystemHosts        atomic.Bool
)

type Hosts struct {
	trie atomic.Pointer[trie.DomainTrie[HostValue]]
}

func NewHosts(hosts *trie.DomainTrie[HostValue]) *Hosts {
	h := &Hosts{}
	h.Store(hosts)
	return h
}

// Store replaces the hosts. A Search that is in progress keeps the ones it started with.
func (h *Hosts) Store(hosts *trie.DomainTrie[HostValue]) {
	h.trie.Store(hosts)
}

// Return the search result and whether to match the parameter `isDomain`
func (h *Hosts) Search(domain string, isDomain bool) (*HostValue, bool) {
	table := h.trie.Load()
	if value := table.Search(domain); value != nil {
		hostValue := value.Data()
		for {
			if isDomain && hostValue.IsDomain {
				return &hostValue, true
			} else {
				if node := table.Search(hostValue.Domain); node != nil {
					hostValue = node.Data()
				} else {
					break
				}
			}
		}
		if isDomain == hostValue.IsDomain {
			return &hostValue, true
		}

		return &hostValue, false
	}

	if !isDomain && !DisableSystemHosts && UseSystemHosts.Load() {
		addr, _ := hosts.LookupStaticHost(domain)
		if hostValue, err := NewHostValue(addr); err == nil {
			return &hostValue, true
		}
	}
	return nil, false
}

type HostValue struct {
	IsDomain bool
	IPs      []netip.Addr
	Domain   string
}

func NewHostValue(value []string) (HostValue, error) {
	isDomain := true
	ips := make([]netip.Addr, 0, len(value))
	domain := ""
	switch len(value) {
	case 0:
		return HostValue{}, errors.New("value is empty")
	case 1:
		host := value[0]
		if ip, err := netip.ParseAddr(host); err == nil {
			ips = append(ips, ip.Unmap())
			isDomain = false
		} else {
			domain = host
		}
	default: // > 1
		isDomain = false
		for _, str := range value {
			if ip, err := netip.ParseAddr(str); err == nil {
				ips = append(ips, ip.Unmap())
			} else {
				return HostValue{}, err
			}
		}
	}
	if isDomain {
		return NewHostValueByDomain(domain)
	}
	return NewHostValueByIPs(ips)
}

func NewHostValueByIPs(ips []netip.Addr) (HostValue, error) {
	if len(ips) == 0 {
		return HostValue{}, errors.New("ip list is empty")
	}
	return HostValue{
		IsDomain: false,
		IPs:      ips,
	}, nil
}

func NewHostValueByDomain(domain string) (HostValue, error) {
	domain = strings.Trim(domain, ".")
	item := strings.Split(domain, ".")
	if len(item) < 2 {
		return HostValue{}, errors.New("invalid domain")
	}
	return HostValue{
		IsDomain: true,
		Domain:   domain,
	}, nil
}

func (hv HostValue) RandIP() (netip.Addr, error) {
	if hv.IsDomain {
		return netip.Addr{}, errors.New("value type is error")
	}
	return hv.IPs[randv2.IntN(len(hv.IPs))], nil
}
