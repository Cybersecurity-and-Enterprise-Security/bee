package forward

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const GenevePort = 6081
const WireguardPort = 8335

type Forwarder struct {
	attackerCapture  *pcap.Handle // Handle to capture packets from the attacker
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

	// Create the connection after we setup WireGuard, because otherwise we can't listen on the Geneve port at the WireGuard IP
	if err := forwarder.setupBeehiveConnection(); err != nil {
		return nil, fmt.Errorf("setting up beehive connection: %w", err)
	}

	if err := forwarder.setupAttackerInject(); err != nil {
		return nil, fmt.Errorf("setting up attacker inject: %w", err)
	}

	return &forwarder, nil
}

func (f *Forwarder) AttackerToBeehiveLoop(ctx context.Context) error {
	packetSource := gopacket.NewPacketSource(f.attackerCapture, layers.LinkTypeEthernet)

	geneve := layers.Geneve{
		Protocol: layers.EthernetTypeIPv4, // IPv4 content
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	udp := layers.UDP{}
	tcp := layers.TCP{}

	udpParser := gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &udp)
	udpParser.IgnoreUnsupported = true
	tcpParser := gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &tcp)
	tcpParser.IgnoreUnsupported = true

	decoded := []gopacket.LayerType{}

	for fragment := range packetSource.Packets() {
		if ctx.Err() != nil {
			return nil
		}

		ipv4FragmentLayer := fragment.Layer(layers.LayerTypeIPv4)
		if ipv4FragmentLayer == nil {
			// Ignore everything that is not IPv4.
			continue
		}
		ipv4Fragment := ipv4FragmentLayer.(*layers.IPv4)

		// Defragment packets to we can send them the the beehive in one piece.
		ipv4, err := f.defragger.DefragIPv4(ipv4Fragment)
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
	return nil
}

func (f *Forwarder) BeehiveToAttackerLoop(ctx context.Context) error {
	buffer := make([]byte, 2000)

	var geneve layers.Geneve
	var ipv4 layers.IPv4
	var udp layers.UDP
	var tcp layers.TCP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeGeneve, &geneve, &ipv4, &udp, &tcp)
	parser.IgnoreUnsupported = true
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

		if err := parser.DecodeLayers(buffer[:n], &decoded); err != nil {
			log.WithError(err).Warn("decoding layers")
			continue
		}

		if len(decoded) < 2 || decoded[0] != layers.LayerTypeGeneve || decoded[1] != layers.LayerTypeIPv4 {
			fmt.Printf("packet has wrong structure: %s\n", decoded)
			continue
		}

		ipv4.SrcIP = f.listenAddress.AsSlice()

		if err := packetBuffer.Clear(); err != nil {
			// At least currently, this error can't occur due do the way the buffer is implemented.
			// However, if that should occur at some point, just create a new buffer instead of clearing the old one.
			packetBuffer = gopacket.NewSerializeBuffer()
		}
		if len(decoded) >= 3 {
			switch decoded[2] {
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
