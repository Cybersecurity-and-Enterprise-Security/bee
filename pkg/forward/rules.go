package forward

import (
	"errors"
	"net/netip"
	"runtime"
	"sync"
)

const (
	ForwardingProtocolTCP     = "tcp"
	ForwardingProtocolUDP     = "udp"
	ForwardingProtocolUnknown = "unknown"
)

var (
	ErrNoDefaultBeehive = errors.New("no default beehive configured")
)

type ForwardingRule struct {
	Protocol       ForwardingProtocol
	Port           int
	BeehiveAddress string
}

type ForwardingProtocol string

type ForwardingRuleStore struct {
	sync.Mutex

	defaultBeehive *netip.AddrPort
	store          map[ForwardingProtocol]map[int]netip.AddrPort
}

func NewForwardingRuleStore() *ForwardingRuleStore {

	return &ForwardingRuleStore{
		Mutex: sync.Mutex{},
		store: map[ForwardingProtocol]map[int]netip.AddrPort{},
	}
}

func (f *ForwardingRuleStore) SetDefaultBeehiveAddress(addr string) {
	f.Lock()
	defer f.Unlock()

	addrPort := netip.AddrPortFrom(netip.MustParseAddr(addr), GenevePort)

	f.defaultBeehive = &addrPort
}

func (f *ForwardingRuleStore) UpdateForwardingRules(newRules []ForwardingRule) {
	f.Lock()
	defer f.Unlock()

	// Build a new map
	newStore := map[ForwardingProtocol]map[int]netip.AddrPort{}
	for _, rule := range newRules {
		if _, ok := newStore[rule.Protocol]; !ok {
			newStore[rule.Protocol] = map[int]netip.AddrPort{}
		}
		newStore[rule.Protocol][rule.Port] = netip.AddrPortFrom(netip.MustParseAddr(rule.BeehiveAddress), GenevePort)
	}

	// Maps are a little problematic regarding their memory usage in Go https://github.com/golang/go/issues/20135
	// To keep it small, we don't add/remove elements from the old map, but rather create a new one and throw away the old one.

	f.store = newStore

	// Make sure the old map is deleted
	runtime.GC()
}

func (f *ForwardingRuleStore) GetDestinationBeehive(protocol ForwardingProtocol, port int) (*netip.AddrPort, error) {
	f.Lock()
	defer f.Unlock()

	protocolMap, ok := f.store[protocol]
	if !ok {
		if f.defaultBeehive == nil {
			return nil, ErrNoDefaultBeehive
		}
		return f.defaultBeehive, nil
	}

	destination, ok := protocolMap[port]
	if !ok {
		if f.defaultBeehive == nil {
			return nil, ErrNoDefaultBeehive
		}
		return f.defaultBeehive, nil
	}

	return &destination, nil
}
