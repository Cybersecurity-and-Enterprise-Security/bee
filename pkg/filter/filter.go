package filter

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// A Filter is a set of rules for packets.
type Filter interface {
	// Matches returns true if the packet is accepted by the rules of the filter.
	Matches(packet []byte) bool
}

// An IPv4Filter is a filter specifically for matching properties of IPv4 packets.
type IPv4Filter struct {
	DestinationAddress *net.IP
}

func (f *IPv4Filter) Matches(data []byte) bool {
	var ipv4 layers.IPv4

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ipv4)
	decoded := make([]gopacket.LayerType, 1)

	// This error indicates that a layer could not be decoded. This isn't a
	// problem, because we check that the first layer is IPv4, which is the only
	// thing that matters.
	_ = parser.DecodeLayers(data, &decoded)

	if len(decoded) == 0 || decoded[0] != layers.LayerTypeIPv4 {
		return false
	}

	return f.checkDestination(&ipv4)
}

func (f *IPv4Filter) checkDestination(ipv4 *layers.IPv4) bool {
	return f.DestinationAddress == nil || f.DestinationAddress.Equal(ipv4.DstIP)
}
