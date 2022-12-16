package socket

import (
	"syscall"
)

// socket simply holds a file descriptor. In this case, it is a file descriptor
// of a socket.
type socket struct {
	fd int
}

func (s *socket) Read(p []byte) (int, error) {
	return syscall.Read(s.fd, p)
}

func (s *socket) Write(p []byte) (int, error) {
	// We need to pass the redundant destination address information to the
	// sendto syscall because this is how it is. If the destination address is
	// zero, the packet will be incoming on the local loopback interface, but we
	// want it to be send to the actual destination
	var destination syscall.SockaddrInet4
	copy(destination.Addr[:], ipv4DestinationAddress(p)[:])

	// Writing to a raw socket (unconnected) should use some variant of send(2),
	// not write(2). Sendto has to be used for connection-less sockets.
	// See send(2).
	err := syscall.Sendto(s.fd, p, 0, &destination)
	if err != nil {
		return 0, err
	}
	return len(p), err
}

func (s *socket) Close() error {
	return syscall.Close(s.fd)
}
