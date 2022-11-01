package forward

import (
	"fmt"
	"net"
)

// InterfaceOf Address returns the network interface of the host with the given
// IP address. If the address does not exist, it returns nil and an error.
func interfaceOfAddress(address net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("could not get interfaces: %w", err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("could not get addresses of interface %s: %w", iface.Name, err)
		}
		for _, ifaceIp := range addrs {
			ifaceAddr, _, err := net.ParseCIDR(ifaceIp.String())
			if err != nil {
				return nil, fmt.Errorf("could not parse address %s: %w", ifaceIp.String(), err)
			}

			if address.Equal(ifaceAddr) {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no network interface found with address %s", address.String())
}
