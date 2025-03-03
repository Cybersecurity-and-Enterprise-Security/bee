package forward

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const GenevePort = 6081

type Forwarder struct {
	attackerCapture  *nflog.Nflog // Handle to capture packets from the attacker
	attackerInjectFd int          // File descriptor of the socket for sending packets to the attacker
	beehiveConn      *net.UDPConn // Geneve connection to the beehive
	listenAddress    netip.Addr   // address on which the bee listens for packets from the attacker

	iface *net.Interface // Interface which we listen on

	defragger *ip4defrag.IPv4Defragmenter // Defragmentation for IPv4 packets.

	wireguardAddress    net.IPNet    // WireGuard address of the bee
	wireguardPrivateKey wgtypes.Key  // the private WireGuard key of this Beehive
	wireguard           netlink.Link // wireguard interface

	beehiveIPRange *net.IPNet // The IP range of the Bees in the WireGuard network.

	link    *netlink.Wireguard
	netns   *netlink.Handle // handle for the network namespace
	netnsFd *netns.NsHandle // file descriptor for the network namespace

	rules *ForwardingRuleStore // store for the forwarding rules
}

func NewForwarder(bind netip.Addr, wireguardAddress, wireguardPrivateKey, beehiveIPRange string) (*Forwarder, error) {
	forwarder := Forwarder{
		defragger:     ip4defrag.NewIPv4Defragmenter(),
		listenAddress: bind,
		rules:         NewForwardingRuleStore(),
	}

	if err := forwarder.setupNetNS(); err != nil {
		return nil, fmt.Errorf("setting up netns: %w", err)
	}

	if err := forwarder.setupWireguard(wireguardPrivateKey, wireguardAddress, beehiveIPRange); err != nil {
		return nil, fmt.Errorf("setting up wireguard: %w", err)
	}

	if err := forwarder.setupAttackerCapture(bind); err != nil {
		return nil, fmt.Errorf("setting up attacker capture: %w", err)
	}

	// Create the connection after we set up WireGuard, because otherwise we can't listen on the Geneve port at the WireGuard IP
	if err := forwarder.setupBeehiveConnection(); err != nil {
		return nil, fmt.Errorf("setting up beehive connection: %w", err)
	}

	if err := forwarder.setupAttackerInject(); err != nil {
		return nil, fmt.Errorf("setting up attacker inject: %w", err)
	}

	return &forwarder, nil
}

func (f *Forwarder) AttackerToBeehiveLoop(ctx context.Context) error {
	geneve := layers.Geneve{
		Protocol: layers.EthernetTypeIPv4, // IPv4 content
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ipv4 := layers.IPv4{}
	udp := layers.UDP{}
	tcp := layers.TCP{}

	ipParser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ipv4)
	ipParser.IgnoreUnsupported = true
	udpParser := gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &udp)
	udpParser.IgnoreUnsupported = true
	tcpParser := gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &tcp)
	tcpParser.IgnoreUnsupported = true

	decoded := []gopacket.LayerType{}

	incomingBuffer := make(chan []byte, 1000)
	err := f.attackerCapture.RegisterWithErrorFunc(
		ctx,
		func(a nflog.Attribute) int {
			incomingBuffer <- *a.Payload
			return 0
		},
		func(err error) int {
			log.WithError(err).Debug("nflog")
			return 0
		},
	)
	if err != nil {
		log.WithError(err).Info("register nflog listener")
		return err
	}

	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := ipParser.DecodeLayers(<-incomingBuffer, &decoded); err != nil {
			log.WithError(err).Warn("ip: decoding layers")
			continue
		}

		if len(decoded) < 1 || decoded[0] != layers.LayerTypeIPv4 {
			// Ignore everything that is not IPv4.
			continue
		}

		// Defragment packets to we can send them the beehive in one piece.
		ipv4, err := f.defragger.DefragIPv4(&ipv4)
		if err != nil {
			return fmt.Errorf("defragment: %w", err)
		}
		if ipv4 == nil {
			// There are still fragments missing.
			continue
		}

		ipv4.DstIP = f.wireguardAddress.IP

		var protocol ForwardingProtocol
		var port int

		if err := buffer.Clear(); err != nil {
			// At least currently, this error can't occur due do the way the buffer is implemented.
			// However, if that should occur at some point, just create a new buffer instead of clearing the old one.
			buffer = gopacket.NewSerializeBuffer()
		}
		switch ipv4.NextLayerType() {
		case layers.LayerTypeUDP:
			if err := udpParser.DecodeLayers(ipv4.Payload, &decoded); err != nil {
				log.WithError(err).Warn("udp: decoding layers")
				continue
			}
			if decoded[0] != layers.LayerTypeUDP {
				log.Warnf("udp: decoded wrong layer type %s", decoded)
				continue
			}
			if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
				log.WithError(err).Warn("udp: setting network layer for checksum")
				continue
			}
			if err := gopacket.Payload(udp.Payload).SerializeTo(buffer, opts); err != nil {
				log.WithError(err).Warn("udp: serializing payload to buffer")
				continue
			}
			if err := udp.SerializeTo(buffer, opts); err != nil {
				log.WithError(err).Warn("udp: serializing to buffer")
				continue
			}
			protocol = ForwardingProtocolUDP
			port = int(udp.DstPort)
		case layers.LayerTypeTCP:
			if err := tcpParser.DecodeLayers(ipv4.Payload, &decoded); err != nil {
				log.WithError(err).Warn("tcp: decoding layers")
				continue
			}
			if decoded[0] != layers.LayerTypeTCP {
				log.Warnf("tcp: decoded wrong layer type %s", decoded)
				continue
			}
			if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
				log.WithError(err).Warn("tcp: setting network layer for checksum")
				continue
			}
			if err := gopacket.Payload(tcp.Payload).SerializeTo(buffer, opts); err != nil {
				log.WithError(err).Warn("tcp: serializing payload to buffer")
				continue
			}
			if err := tcp.SerializeTo(buffer, opts); err != nil {
				log.WithError(err).Warn("tcp: serializing to buffer")
				continue
			}
			protocol = ForwardingProtocolTCP
			port = int(tcp.DstPort)
		default:
			if err := gopacket.Payload(ipv4.Payload).SerializeTo(buffer, opts); err != nil {
				log.WithError(err).Warn("serialize ip payload")
				continue
			}
			protocol = ForwardingProtocolUnknown
		}

		if err := ipv4.SerializeTo(buffer, opts); err != nil {
			log.WithError(err).Warn("serialize ipv4: %w", err)
			continue
		}

		if err := geneve.SerializeTo(buffer, opts); err != nil {
			log.WithError(err).Warn("serialize geneve")
			continue
		}

		destinationBeehive, err := f.rules.GetDestinationBeehive(protocol, port)
		if err != nil {
			return fmt.Errorf("getting destination beehive: %w", err)
		}

		if _, err := f.beehiveConn.WriteToUDP(buffer.Bytes(), net.UDPAddrFromAddrPort(*destinationBeehive)); err != nil {
			return fmt.Errorf("send packet to beehive: %w", err)
		}
	}
}

func (f *Forwarder) BeehiveToAttackerLoop(ctx context.Context) error {
	buffer := make([]byte, 2000)

	var geneve layers.Geneve
	var ipv4 layers.IPv4
	var udp layers.UDP
	var tcp layers.TCP
	// We use separate parsers for the outer geneve layer we added ourselves and the inner layers for the attacker.
	// We cannot use a single parser for both, because if the beehive wants to send a packet from or to the geneve port,
	// the parser would produce a packet of the structure [geneve - ip - udp - geneve]. This is because layers.UDP guesses
	// the next layer from the src/dst ports. If we parsed UDP and geneve in the same parser, we could thus unintentionally parse
	// the payload of UDP packets. We now parse these separately, so UDP.NextLayerType can still be geneve, but the parser
	// does not have a DecodingLayer for geneve. Because IgnoreUnsupported is true, parsing terminates and the UDP payload
	// stays opaque, as it should.
	geneveParser := gopacket.NewDecodingLayerParser(layers.LayerTypeGeneve, &geneve)
	geneveParser.IgnoreUnsupported = true
	innerParser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ipv4, &udp, &tcp)
	innerParser.IgnoreUnsupported = true
	decoded := []gopacket.LayerType{}

	packetBuffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := f.beehiveConn.Read(buffer)
		if err != nil {
			// The read call terminates with "use of closed network connection" if we stop the program
			// because of a signal. Hence, we simply ignore any errors if the context has been canceled.
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("receive packet: %w", err)
		}

		if err := geneveParser.DecodeLayers(buffer[:n], &decoded); err != nil {
			log.WithError(err).Warn("decoding geneve")
			continue
		}

		if len(decoded) < 1 || decoded[0] != layers.LayerTypeGeneve {
			log.WithField("layers", decoded).Warn("packet is not geneve")
			continue
		}

		if err := innerParser.DecodeLayers(geneve.Payload, &decoded); err != nil {
			log.WithError(err).Warn("decoding inner layers")
			continue
		}

		if len(decoded) < 1 || decoded[0] != layers.LayerTypeIPv4 {
			log.WithField("layers", decoded).Warn("inner packet has wrong structure")
			continue
		}

		ipv4.SrcIP = f.listenAddress.AsSlice()

		if err := packetBuffer.Clear(); err != nil {
			// At least currently, this error can't occur due do the way the buffer is implemented.
			// However, if that should occur at some point, just create a new buffer instead of clearing the old one.
			packetBuffer = gopacket.NewSerializeBuffer()
		}
		if len(decoded) >= 2 {
			switch decoded[1] {
			case layers.LayerTypeUDP:
				if err := udp.SetNetworkLayerForChecksum(&ipv4); err != nil {
					log.WithError(err).Warn("udp: setting network layer for checksum")
					continue
				}
				if err := gopacket.Payload(udp.Payload).SerializeTo(packetBuffer, opts); err != nil {
					log.WithError(err).Warn("udp: serialize payload")
					continue
				}
				if err := udp.SerializeTo(packetBuffer, opts); err != nil {
					log.WithError(err).Warn("udp: serialize")
					continue
				}
			case layers.LayerTypeTCP:
				if err := tcp.SetNetworkLayerForChecksum(&ipv4); err != nil {
					log.WithError(err).Warn("tcp: setting network layer for checksum")
					continue
				}
				if err := gopacket.Payload(tcp.Payload).SerializeTo(packetBuffer, opts); err != nil {
					log.WithError(err).Warn("tcp: serialize payload")
					continue
				}
				if err := tcp.SerializeTo(packetBuffer, opts); err != nil {
					log.WithError(err).Warn("tcp: serialize")
					continue
				}
			default:
				if err := gopacket.Payload(ipv4.Payload).SerializeTo(packetBuffer, opts); err != nil {
					log.WithError(err).Warn("serialize ip payload")
					continue
				}
			}
		} else {
			if err := gopacket.Payload(ipv4.Payload).SerializeTo(packetBuffer, opts); err != nil {
				log.WithError(err).Warn("serialize ip payload")
				continue
			}
		}

		var sockAddr syscall.SockaddrInet4
		copy(sockAddr.Addr[:], ipv4.DstIP)

		maxPayloadSize := f.iface.MTU - 20 // We assume the IP header is always 20 bytes long.
		if maxPayloadSize >= len(packetBuffer.Bytes()) {
			ipv4.FragOffset = 0
			ipv4.Flags &^= layers.IPv4MoreFragments
			if err := ipv4.SerializeTo(packetBuffer, opts); err != nil {
				log.WithError(err).Warn("serialize ipv4")
				continue
			}
			if err := syscall.Sendto(f.attackerInjectFd, packetBuffer.Bytes(), 0, &sockAddr); err != nil {
				return fmt.Errorf("send packet to attacker: %w", err)
			}
			continue
		}

		// Needs fragmentation.
		fragmentSize := 8 * (maxPayloadSize / 8)
		payload := make([]byte, len(packetBuffer.Bytes()))
		copy(payload[:], packetBuffer.Bytes())

		for offset := 0; offset < len(payload); offset += fragmentSize {
			if err := packetBuffer.Clear(); err != nil {
				log.WithError(err).Warn("clearing serialization buffer")
				continue
			}
			if err := gopacket.Payload(payload[offset:min(len(payload), offset+fragmentSize)]).SerializeTo(packetBuffer, opts); err != nil {
				log.WithError(err).Warn("serialize ip payload")
				continue
			}
			ipv4.Flags &^= layers.IPv4DontFragment
			ipv4.FragOffset = uint16(offset / 8)
			if offset+fragmentSize <= maxPayloadSize {
				ipv4.Flags |= layers.IPv4MoreFragments
			} else {
				ipv4.Flags &^= layers.IPv4MoreFragments
			}
			if err := ipv4.SerializeTo(packetBuffer, opts); err != nil {
				log.WithError(err).Warn("serialize ipv4")
				continue
			}
			if err := syscall.Sendto(f.attackerInjectFd, packetBuffer.Bytes(), 0, &sockAddr); err != nil {
				return fmt.Errorf("send packet to attacker: %w", err)
			}
		}
	}
}

func (f *Forwarder) UpdateForwardingRules(newRules []ForwardingRule) {
	f.rules.UpdateForwardingRules(newRules)
}

func (f *Forwarder) SetDefaultBeehiveAddress(addr string) error {
	return f.rules.SetDefaultBeehiveAddress(addr)
}
