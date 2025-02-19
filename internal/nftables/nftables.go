package nftables

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/prometheus/procfs"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:embed bee-nftables.conf
var templateNftables string

func ConfigureNftables(listenAddress netip.Addr, ignoredTcpPorts, ignoredUdpPorts []int) error {
	listenIP := net.IP(listenAddress.AsSlice())
	// Open the proc filesystem to read open ports
	pfs, err := procfs.NewDefaultFS()
	if err != nil {
		return fmt.Errorf("opening proc filesystem: %w", err)
	}

	tcpPorts, err := getOpenTCPPorts(pfs, listenIP)
	if err != nil {
		return fmt.Errorf("getting open TCP ports: %w", err)
	}
	udpPorts, err := getOpenUDPPorts(pfs, listenIP)
	if err != nil {
		return fmt.Errorf("getting open UDP ports: %w", err)
	}

	if err := installBaseNftables(listenIP); err != nil {
		return fmt.Errorf("installing base nftables: %w", err)
	}

	tcpPorts = mergeAndSortPorts(tcpPorts, ignoredTcpPorts)
	udpPorts = mergeAndSortPorts(udpPorts, ignoredUdpPorts)

	log.
		WithField("ignoredTCP", tcpPorts).
		WithField("ignoredUDP", udpPorts).
		Info("Not exposing ports because they are ignored or local applications are listening on them")

	if err := addOpenTCPPorts(tcpPorts...); err != nil {
		return fmt.Errorf("adding open tcp ports: %w", err)
	}

	if err := addOpenUDPPorts(udpPorts...); err != nil {
		return fmt.Errorf("adding open udp ports: %w", err)
	}

	return nil
}

func RemoveNftables() error {
	cmd := nftablesCommand("delete", "table", "inet", "bee_filter")
	return runNftablesCommand(cmd)
}

// socketsConflict returns true if a socket listening on ip conflicts with.
func socketsConflict(ip, listen net.IP) bool {
	return ip.IsUnspecified() || ip.Equal(listen)
}

func getOpenTCPPorts(pfs procfs.FS, listenIP net.IP) ([]int, error) {
	// Read the TCP connection information
	ipv4TcpConns, err := pfs.NetTCP()
	if err != nil {
		return nil, fmt.Errorf("reading TCP connection information for IPv4: %w", err)
	}
	ipv6TcpConns, err := pfs.NetTCP6()
	if err != nil {
		return nil, fmt.Errorf("reading TCP connection information for IPv6: %w", err)
	}

	// Extract the open ports from the TCP connections
	ports := make(map[int]struct{})
	tcpConns := make(procfs.NetTCP, 0, len(ipv4TcpConns)+len(ipv6TcpConns))
	tcpConns = append(tcpConns, ipv4TcpConns...)
	tcpConns = append(tcpConns, ipv6TcpConns...)
	for _, conn := range tcpConns {
		// See https://github.com/torvalds/linux/blob/master/include/net/tcp_states.h#L22
		// for the list of states.
		if conn.St == netlink.TCP_LISTEN && conn.Inode != 0 {
			if socketsConflict(conn.LocalAddr, listenIP) {
				ports[int(conn.LocalPort)] = struct{}{}
			}
		}
	}

	portList := make([]int, 0, len(ports))
	for port := range ports {
		portList = append(portList, port)
	}
	return portList, nil
}

func getOpenUDPPorts(pfs procfs.FS, listenIP net.IP) ([]int, error) {
	// Read the UDP connection information
	ipv4UdpConns, err := pfs.NetUDP()
	if err != nil {
		return nil, fmt.Errorf("reading UDP connection information for IPv4: %w", err)
	}
	ipv6UdpConns, err := pfs.NetUDP6()
	if err != nil {
		return nil, fmt.Errorf("reading UDP connection information for IPv6: %w", err)
	}

	// Extract the open ports from the UDP connections
	ports := make(map[int]struct{})
	udpConns := make(procfs.NetUDP, 0, len(ipv4UdpConns)+len(ipv6UdpConns))
	udpConns = append(udpConns, ipv4UdpConns...)
	udpConns = append(udpConns, ipv6UdpConns...)
	for _, conn := range udpConns {
		// In contrast to TCP, UDP doesn't really have a LISTENING state.
		// (See https://github.com/torvalds/linux/blob/master/net/ipv4/udp.c which only uses TCP_CLOSE and TCP_ESTABLISHED)
		// For now, we use all UDP ports to better be safe than sorry.
		// Maybe, we could only use the ports whose remote address is null, or even those in state 7.
		if conn.Inode != 0 {
			if socketsConflict(conn.LocalAddr, listenIP) {
				ports[int(conn.LocalPort)] = struct{}{}
			}
		}
	}

	portList := make([]int, 0, len(ports))
	for port := range ports {
		portList = append(portList, port)
	}
	return portList, nil
}

func installBaseNftables(listenIP net.IP) error {
	cmd := nftablesCommand("-f", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf(templateNftables, listenIP))

	if err := runNftablesCommand(cmd); err != nil {
		return fmt.Errorf("running nftables: %w", err)
	}

	return nil
}

func addOpenTCPPorts(ports ...int) error {
	if len(ports) == 0 {
		return nil
	}

	portsString := make([]string, 0, len(ports))
	for _, p := range ports {
		portsString = append(portsString, strconv.Itoa(p))
	}

	cmd := nftablesCommand(
		"add",
		"element",
		"inet",
		"bee_filter",
		"open_tcp_ports",
		fmt.Sprintf("{ %s }", strings.Join(portsString, ",")),
	)

	if err := runNftablesCommand(cmd); err != nil {
		return fmt.Errorf("running nftables: %w", err)
	}

	return nil
}

func addOpenUDPPorts(ports ...int) error {
	if len(ports) == 0 {
		return nil
	}

	portsString := make([]string, 0, len(ports))
	for _, p := range ports {
		portsString = append(portsString, strconv.Itoa(p))
	}

	cmd := nftablesCommand(
		"add",
		"element",
		"inet",
		"bee_filter",
		"open_udp_ports",
		fmt.Sprintf("{ %s }", strings.Join(portsString, ",")),
	)

	if err := runNftablesCommand(cmd); err != nil {
		return fmt.Errorf("running nftables: %w", err)
	}

	return nil
}

func nftablesCommand(args ...string) *exec.Cmd {
	cmd := exec.Command("/usr/sbin/nft", args...)
	// Pass the CAP_NET_ADMIN capability to the process.
	// This way, we can use the nft tool without root (if CAP_NET_ADMIN is set on ourself).
	cmd.SysProcAttr = &syscall.SysProcAttr{
		AmbientCaps: []uintptr{
			unix.CAP_NET_ADMIN,
		},
	}
	return cmd
}

func runNftablesCommand(cmd *exec.Cmd) error {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("output: %v | error: %w", stderr.String(), err)
	}

	return nil
}

func mergeAndSortPorts(openPorts, ignoredPorts []int) []int {
	ports := []int{}
	ports = append(ports, openPorts...)
	ports = append(ports, ignoredPorts...)
	slices.Sort(ports)
	ports = slices.Compact(ports)
	return ports
}
