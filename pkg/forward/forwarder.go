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
)

const GenevePort = 6081
const WireguardPort = 8335

type Forwarder struct {
	attackerCapture  *pcap.Handle // Handle to capture packets from the attacker
	attackerInjectFd int          // File descriptor of the socket for sending packets to the attacker
	beehiveConn      *net.UDPConn // Geneve connection to the beehive
	wireguardAddress netip.Addr   // WireGuard address of the bee
	listenAddress    netip.Addr   // address on which the bee listens for packets from the attacker

	defragger *ip4defrag.IPv4Defragmenter // Defragmentation for IPv4 packets.

	beehiveGeneveAddress netip.AddrPort // (temporary) WireGuard Geneve address of the beehive
}

func NewForwarder(bind netip.Addr, wireguardAddress netip.Addr) (*Forwarder, error) {
	beehiveGeneveAddress := netip.AddrPortFrom(netip.MustParseAddr("10.64.0.1"), GenevePort)

	iface, err := interfaceOfAddress(bind)
	if err != nil {
		return nil, fmt.Errorf("get interface with address: %w", err)
	}

	handle, err := pcap.NewInactiveHandle(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("create inactive handle: %w", err)
	}
	if err := handle.SetImmediateMode(true); err != nil {
		return nil, fmt.Errorf("set immediate mode: %w", err)
	}
	if err := handle.SetTimeout(pcap.BlockForever); err != nil {
		return nil, fmt.Errorf("set timeout: %w", err)
	}
	if err := handle.SetSnapLen(1600); err != nil {
		return nil, fmt.Errorf("set snap length: %w", err)
	}

	attackerCapture, err := handle.Activate()
	if err != nil {
		return nil, fmt.Errorf("activate handle: %w", err)
	}
	if err := attackerCapture.SetBPFFilter(fmt.Sprintf("host %s", bind)); err != nil {
		return nil, fmt.Errorf("set BPF filter: %w", err)
	}
	if err := attackerCapture.SetDirection(pcap.DirectionIn); err != nil {
		return nil, fmt.Errorf("set direction: %w", err)
	}

	beehiveConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: wireguardAddress.AsSlice(), Port: GenevePort})
	if err != nil {
		return nil, fmt.Errorf("connect to beehive: %w", err)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("create raw socket: %w", err)
	}
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface.Name); err != nil {
		return nil, fmt.Errorf("bind raw socket: %w", err)
	}

	return &Forwarder{
		attackerCapture:      attackerCapture,
		attackerInjectFd:     fd,
		beehiveConn:          beehiveConn,
		defragger:            ip4defrag.NewIPv4Defragmenter(),
		listenAddress:        bind,
		wireguardAddress:     wireguardAddress,
		beehiveGeneveAddress: beehiveGeneveAddress,
	}, nil
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

		ipv4.DstIP = f.wireguardAddress.AsSlice()

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
		case layers.LayerTypeTCP:
			tcpParser.DecodeLayers(ipv4.Payload, &decoded)
			if decoded[0] != layers.LayerTypeTCP {
				return fmt.Errorf("decode tcp: wrong layer type %s", decoded)
			}
			tcp.SetNetworkLayerForChecksum(ipv4)
			gopacket.Payload(tcp.Payload).SerializeTo(buffer, opts)
			tcp.SerializeTo(buffer, opts)
		default:
			if err := gopacket.Payload(ipv4.Payload).SerializeTo(buffer, opts); err != nil {
				return fmt.Errorf("serialize ip payload: %w", err)
			}
		}

		if err := ipv4.SerializeTo(buffer, opts); err != nil {
			return fmt.Errorf("serialize ipv4: %w", err)
		}

		if err := geneve.SerializeTo(buffer, opts); err != nil {
			return fmt.Errorf("serialize geneve: %w", err)
		}

		// TODO: perform beehive address lookup by (destination address, ip protocol, port?)
		if _, err := f.beehiveConn.WriteToUDP(buffer.Bytes(), net.UDPAddrFromAddrPort(f.beehiveGeneveAddress)); err != nil {
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
