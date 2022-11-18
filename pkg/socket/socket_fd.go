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
	// Writing to a raw socket (unconnected) should use some variant of send(2),
	// not write(2). See send(2).
	err := syscall.Sendto(s.fd, p, 0, &syscall.SockaddrInet4{})
	if err != nil {
		return 0, err
	}
	return len(p), err
}

func (s *socket) Close() error {
	return syscall.Close(s.fd)
}
