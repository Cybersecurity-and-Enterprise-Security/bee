package socket

import "syscall"

// socket simply holds a file descriptor. In this case, it is a file descriptor
// of a socket.
type socket struct {
	fd int
}

func (s *socket) Read(p []byte) (int, error) {
	return syscall.Read(s.fd, p)
}

func (s *socket) Write(p []byte) (int, error) {
	return syscall.Write(s.fd, p)
}

func (s *socket) Close() error {
	return syscall.Close(s.fd)
}
