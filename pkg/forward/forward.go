package forward

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"

	log "github.com/sirupsen/logrus"
	"gitlab.cyber-threat-intelligence.com/software/alvarium/bee/pkg/filter"
	"gitlab.cyber-threat-intelligence.com/software/alvarium/bee/pkg/socket"
)

// packetBufferSize is the buffer size allocated to receive one packet.
// This value should be at least as large as the length of the largest expected
// packet.
const packetBufferSize = 4096

// A Forwarder is responsible for relaying packets back and forth between the
// socket and tunnel.
type Forwarder struct {
	// receiveFilter is a Filter to apply before forwarding packets from the socket to the tunnel.
	receiveFilter filter.Filter
	// sendFilter is a Filter to apply before forwarding packets from the tunnel to the socket.
	sendFilter filter.Filter
	socket     io.ReadWriteCloser
	tunnel     io.ReadWriteCloser
}

// NewForwarder creates a new forwarder. The new forwarder relays packets
// between the bind address and the beehive after forwarder.Forward has been
// called on it. On error, it returns nil and an error.
func NewForwarder(bindAddressString string, beehiveAddress string) (*Forwarder, error) {
	bindAddress := net.ParseIP(bindAddressString)
	if bindAddress == nil {
		return nil, fmt.Errorf("could not parse address %s", bindAddress)
	}

	bindInterface, err := interfaceOfAddress(bindAddress)
	if err != nil {
		return nil, fmt.Errorf("finding address of interface: %w", err)
	}

	socket, err := socket.NewRawSocketIPv4(bindInterface)
	if err != nil {
		return nil, fmt.Errorf("creating new raw IPv4 socket: %w", err)
	}

	tunnel, err := net.Dial("udp", beehiveAddress)
	if err != nil {
		return nil, fmt.Errorf("connecting to beehive: %w", err)
	}

	sendFilter := &filter.IPv4Filter{}
	receiveFilter := &filter.IPv4Filter{DestinationAddress: &bindAddress}

	return &Forwarder{
		sendFilter:    sendFilter,
		receiveFilter: receiveFilter,
		socket:        socket,
		tunnel:        tunnel,
	}, nil
}

// Close closes the forwarder and all associated sockets. This also ends all
// forwarding currently in progress.
func (f *Forwarder) Close() {
	f.socket.Close()
	f.tunnel.Close()
}

// Forward is a blocking function that starts the forwarding procedure. It takes
// a context and terminates when this context is done.
func (f *Forwarder) Forward(ctx context.Context) error {
	ch := make(chan error, 2)

	go func() {
		ch <- f.socketToTunnel(ctx)
	}()
	go func() {
		ch <- f.tunnelToSocket(ctx)
	}()

	select {
	case <-ctx.Done():
		f.Close()
		return nil
	case err := <-ch:
		f.Close()
		return fmt.Errorf("forwarding ended unexpectedly: %w", err)
	}
}

func (f *Forwarder) socketToTunnel(ctx context.Context) error {
	var nRead, nWrite int
	var err error
	packet := make([]byte, packetBufferSize)

	for {
		if ctx.Err() != nil {
			return nil
		}
		if nRead, err = f.socket.Read(packet); err != nil {
			return fmt.Errorf("read from socket: %w", err)
		}
		if !f.receiveFilter.Matches(packet[:nRead]) {
			continue
		}

		log.
			WithField("data", hex.EncodeToString(packet[:nRead])).
			Debug("Sending data to tunnel")

		if nWrite, err = f.tunnel.Write(packet[:nRead]); err != nil {
			return fmt.Errorf("write to tunnel: %w", err)
		}
		if nWrite != nRead {
			return errors.New("socketToTunnel: could not write full packet")
		}
	}
}

func (f *Forwarder) tunnelToSocket(ctx context.Context) error {
	var nRead, nWrite int
	var err error
	packet := make([]byte, packetBufferSize)

	for {
		if ctx.Err() != nil {
			return nil
		}
		if nRead, err = f.tunnel.Read(packet); err != nil {
			return fmt.Errorf("read from tunnel: %w", err)
		}
		if !f.sendFilter.Matches(packet[:nRead]) {
			continue
		}

		log.
			WithField("data", hex.EncodeToString(packet[:nRead])).
			Debug("Sending data to socket")

		if nWrite, err = f.socket.Write(packet[:nRead]); err != nil {
			return fmt.Errorf("write to socket: %w", err)
		}
		if nWrite != nRead {
			return errors.New("tunnelToSocket: could not write full packet")
		}
	}
}
