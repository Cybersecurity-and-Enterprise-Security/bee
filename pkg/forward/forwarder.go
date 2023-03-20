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
	tcpParser := gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &tcp)
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

		buffer.Clear()
		switch ipv4.NextLayerType() {
		case layers.LayerTypeUDP:
			udpParser.DecodeLayers(ipv4.Payload, &decoded)
			if decoded[0] != layers.LayerTypeUDP {
				return fmt.Errorf("decode udp: wrong layer type %s", decoded)
			}
			udp.SetNetworkLayerForChecksum(ipv4)
			gopacket.Payload(udp.Payload).SerializeTo(buffer, opts)
			udp.SerializeTo(buffer, opts)
			protocol = ForwardingProtocolUDP
			port = int(udp.DstPort)
		case layers.LayerTypeTCP:
			tcpParser.DecodeLayers(ipv4.Payload, &decoded)
			if decoded[0] != layers.LayerTypeTCP {
				return fmt.Errorf("decode tcp: wrong layer type %s", decoded)
			}
			tcp.SetNetworkLayerForChecksum(ipv4)
			gopacket.Payload(tcp.Payload).SerializeTo(buffer, opts)
			tcp.SerializeTo(buffer, opts)
			protocol = ForwardingProtocolTCP
			port = int(tcp.DstPort)
		default:
			if err := gopacket.Payload(ipv4.Payload).SerializeTo(buffer, opts); err != nil {
				return fmt.Errorf("serialize ip payload: %w", err)
			}
			protocol = ForwardingProtocolUnknown
		}

		if err := ipv4.SerializeTo(buffer, opts); err != nil {
			return fmt.Errorf("serialize ipv4: %w", err)
		}

		if err := geneve.SerializeTo(buffer, opts); err != nil {
			return fmt.Errorf("serialize geneve: %w", err)
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
			return fmt.Errorf("receive packet: %w", err)
		}

		parser.DecodeLayers(buffer[:n], &decoded)

		if len(decoded) < 2 || decoded[0] != layers.LayerTypeGeneve || decoded[1] != layers.LayerTypeIPv4 {
			fmt.Printf("packet has wrong structure: %s\n", decoded)
			continue
		}

		ipv4.SrcIP = f.listenAddress.AsSlice()

		packetBuffer.Clear()
		if len(decoded) >= 3 {
			switch decoded[2] {
			case layers.LayerTypeUDP:
				udp.SetNetworkLayerForChecksum(&ipv4)
				if err := gopacket.Payload(udp.Payload).SerializeTo(packetBuffer, opts); err != nil {
					return fmt.Errorf("serialize udp payload: %w", err)
				}
				if err := udp.SerializeTo(packetBuffer, opts); err != nil {
					return fmt.Errorf("serialize udp: %w", err)
				}
			case layers.LayerTypeTCP:
				tcp.SetNetworkLayerForChecksum(&ipv4)
				if err := gopacket.Payload(tcp.Payload).SerializeTo(packetBuffer, opts); err != nil {
					return fmt.Errorf("serialize tcp payload: %w", err)
				}
				if err := tcp.SerializeTo(packetBuffer, opts); err != nil {
					return fmt.Errorf("serialize tcp: %w", err)
				}
			default:
				if err := gopacket.Payload(ipv4.Payload).SerializeTo(packetBuffer, opts); err != nil {
					return fmt.Errorf("serialize ip payload: %w", err)
				}
			}
		} else {
			if err := gopacket.Payload(ipv4.Payload).SerializeTo(packetBuffer, opts); err != nil {
				return fmt.Errorf("serialize ip payload: %w", err)
			}
		}

		if err := ipv4.SerializeTo(packetBuffer, opts); err != nil {
			return fmt.Errorf("serialize ipv4: %w", err)
		}

		var sockAddr syscall.SockaddrInet4
		copy(sockAddr.Addr[:], ipv4.DstIP)
		if err := syscall.Sendto(f.attackerInjectFd, packetBuffer.Bytes(), 0, &sockAddr); err != nil {
			return fmt.Errorf("send packet to attacker: %w", err)
		}
	}
}

func (f *Forwarder) UpdateForwardingRules(newRules []ForwardingRule) {
	f.rules.UpdateForwardingRules(newRules)
}

func (f *Forwarder) SetDefaultBeehiveAddress(addr string) {
	f.rules.SetDefaultBeehiveAddress(addr)
}
