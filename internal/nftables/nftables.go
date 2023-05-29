package nftables

import (
	"bytes"
	_ "embed"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

//go:embed bee-nftables.conf
var templateNftables string

func ConfigureNftables(listenIP string) error {
	// Open the proc filesystem to read open ports
	pfs, err := procfs.NewDefaultFS()
	if err != nil {
		return fmt.Errorf("opening proc filesystem: %w", err)
	}

	tcpPorts, err := getOpenTCPPorts(pfs)
	if err != nil {
		return fmt.Errorf("getting open TCP ports: %w", err)
	}
	udpPorts, err := getOpenUDPPorts(pfs)
	if err != nil {
		return fmt.Errorf("getting open UDP ports: %w", err)
	}

	if err := installBaseNftables(listenIP); err != nil {
		return fmt.Errorf("installing base nftables: %w", err)
	}

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

func getOpenTCPPorts(pfs procfs.FS) ([]uint64, error) {
	// Read the TCP connection information
	tcpConns, err := pfs.NetTCP()
	if err != nil {
		return nil, fmt.Errorf("reading TCP connection information: %w", err)
	}

	// Extract the open ports from the TCP connections
	ports := []uint64{}
	for _, conn := range tcpConns {
		// See https://github.com/torvalds/linux/blob/master/include/net/tcp_states.h#L22
		// for the list of states.
		// 10 is TCP_LISTEN.
		if conn.St == 10 && conn.Inode != 0 {
			ports = append(ports, conn.LocalPort)
		}
	}

	return ports, nil
}

func getOpenUDPPorts(pfs procfs.FS) ([]uint64, error) {
	// Read the UDP connection information
	udpConns, err := pfs.NetUDP()
	if err != nil {
		return nil, fmt.Errorf("reading UDP connection information: %w", err)
	}

	// Extract the open ports from the UDP connections
	ports := []uint64{}
	for _, conn := range udpConns {
		// In contrast to TCP, UDP doesn't really have a LISTENING state.
		// (See https://github.com/torvalds/linux/blob/master/net/ipv4/udp.c which only uses TCP_CLOSE and TCP_ESTABLISHED)
		// For now, we use all UDP ports to better be safe than sorry.
		// Maybe, we could only use the ports whose remote address is null, or even those in state 7.
		if conn.Inode != 0 {
			ports = append(ports, conn.LocalPort)
		}
	}

	return ports, nil
}

func installBaseNftables(listenIP string) error {
	cmd := nftablesCommand("-f", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf(templateNftables, listenIP))

	if err := runNftablesCommand(cmd); err != nil {
		return fmt.Errorf("running nftables: %w", err)
	}

	return nil
}

func addOpenTCPPorts(ports ...uint64) error {
	if len(ports) == 0 {
		return nil
	}

	portsString := make([]string, 0, len(ports))
	for _, p := range ports {
		portsString = append(portsString, strconv.Itoa(int(p)))
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

func addOpenUDPPorts(ports ...uint64) error {
	if len(ports) == 0 {
		return nil
	}

	portsString := make([]string, 0, len(ports))
	for _, p := range ports {
		portsString = append(portsString, strconv.Itoa(int(p)))
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
