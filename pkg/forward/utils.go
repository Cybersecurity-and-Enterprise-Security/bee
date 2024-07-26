package forward

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// interfaceOfAddress returns the network interface of the host with the given
// IP address. If the address does not exist, it returns nil and an error.
func interfaceOfAddress(address netip.Addr) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("get interfaces: %w", err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("get addresses of interface %s: %w", iface.Name, err)
		}
		for _, ifaceIP := range addrs {
			ifaceAddr, err := netip.ParseAddr(strings.Split(ifaceIP.String(), "/")[0])
			if err != nil {
				return nil, fmt.Errorf("parse address %s: %w", ifaceIP.String(), err)
			}

			if address == ifaceAddr {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface with address %s", address.String())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
