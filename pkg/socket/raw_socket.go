package socket

import (
	"fmt"
	"io"
	"net"
	"syscall"
)

// PACKET_IGNORE_OUTGOING is the socket option for packet sockets to ignore
// outgoing packets. Go's syscall package does not contain this constant :(
const PACKET_IGNORE_OUTGOING = 23

// NETWORK_BYTEORDER_ETH_P_IP is the constant ETH_P_IP in big endian byte order.
// For creating a packet(7) socket using the socket syscall, we need to specify
// the protocol as a uint16 in network byte order. The manpage suggests using
// the `htons` function from the C standard library on the defined constant.
// Since Go doesn't provide a convenient way to convert from host byte order to
// network byte order, this value is pre-calculated for the
// syscall.ETH_P_IP = 2048 constant. 2048 = 0x0800 in little endian
// and 0x0080 = 8 in big endian byte order.
const NETWORK_BYTEORDER_ETH_P_IP = 8

// A RawSocket is a socket capable of reading and writing arbitrary IP packets.
// Because one raw IP socket only allows to receive one IP protocol (e.g. TCP,
// UDP, ICMP, ...) and it is not possible to receive IP packets with protocol
// id 0, we use a packet(7) socket for receiving. Because we don't want to
// provide the link-layer header when sending packets, we don't also use this
// packet socket to send. For sending, a raw IP socket is sufficient. Therefore,
// RawSocket uses different socket for both operations but exposes them both by
// implementing the io.ReadWriteCloser interface.
type RawSocket struct {
	sendingSocket   io.WriteCloser
	receivingSocket io.ReadCloser
}

// NewRawSocketIPv4 creates a new RawSocket for the IPv4 address family. On
// error, it returns nil and an error
func NewRawSocketIPv4(bindInterface *net.Interface) (*RawSocket, error) {
	sendingSocket, err := newSendingRawSocketIPv4(bindInterface)
	if err != nil {
		return nil, fmt.Errorf("create sending raw IPv4 socket: %w", err)
	}

	receivingSocket, err := newReceivingRawSocketIPv4(bindInterface)
	if err != nil {
		return nil, fmt.Errorf("create receiving raw IPv4 socket: %w", err)
	}

	return &RawSocket{
		sendingSocket:   sendingSocket,
		receivingSocket: receivingSocket,
	}, nil
}

func (s *RawSocket) Read(p []byte) (int, error) {
	return s.receivingSocket.Read(p)
}

func (s *RawSocket) Write(p []byte) (int, error) {
	return s.sendingSocket.Write(p)
}

func (s *RawSocket) Close() error {
	s.sendingSocket.Close()
	s.receivingSocket.Close()
	return nil
}

func newSendingRawSocketIPv4(bindInterface *net.Interface) (io.WriteCloser, error) {
	// IPPROTO_RAW gives us complete control over the IPv4 header, but it is
	// send-only (see raw(7)).
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("create raw socket (AF_INET, SOCK_RAW, IPPROTO_RAW): %w", err)
	}

	// Bind the socket to the device using Setsockopt and SO_BINDTODEVICE for
	// raw sockets.
	err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, bindInterface.Name)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind socket to device: %w", err)
	}

	return &socket{fd: fd}, nil
}

func newReceivingRawSocketIPv4(bindInterface *net.Interface) (io.ReadCloser, error) {

	// This is a packet socket (see packet(7)). It receives all IPv4 packets.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, NETWORK_BYTEORDER_ETH_P_IP)
	if err != nil {
		return nil, fmt.Errorf("create raw socket (AF_PACKET, SOCK_DGRAM, ETH_P_IP): %w", err)
	}

	// We are not interested in outgoing packets.
	err = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("set PACKET_IGNORE_OUTGOING on socket: %w", err)
	}

	// Bind the socket to the device using bind for packet sockets.
	if err = syscall.Bind(fd, &syscall.SockaddrLinklayer{Ifindex: bindInterface.Index}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind socket to interface: %w", err)
	}

	return &socket{fd: fd}, nil
}
