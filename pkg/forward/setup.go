package forward

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// setupNetNS creates a handle to the current network namespace.
func (f *Forwarder) setupNetNS() error {
	currentNetnsFd, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get init netns: %w", err)
	}

	currentNetns, err := netlink.NewHandleAt(netns.None())
	if err != nil {
		return fmt.Errorf("get handle for init netns: %w", err)
	}

	f.netnsFd = &currentNetnsFd
	f.netns = currentNetns

	return nil
}

// setupWireguard creates and configures the WireGuard interface.
func (f *Forwarder) setupWireguard(wireguardPrivateKey, wireguardAddress, beehiveRange string) error {
	var err error

	f.wireguardPrivateKey, err = wgtypes.ParseKey(wireguardPrivateKey)
	if err != nil {
		return fmt.Errorf("parsing wireguard private key: %w", err)
	}

	f.wireguardAddress = net.IPNet{
		IP:   net.ParseIP(wireguardAddress),
		Mask: net.CIDRMask(32, 32),
	}

	_, f.beehiveIPRange, err = net.ParseCIDR(beehiveRange)
	if err != nil {
		return fmt.Errorf("parsing beehive ip range: %w", err)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = IfNameWireguard

	link := &netlink.Wireguard{
		LinkAttrs: attrs,
	}

	if err := f.netns.LinkAdd(link); err != nil {
		return fmt.Errorf("add wireguard link: %w", err)
	}

	f.link = link

	wgctrlClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("create wgctrl client: %w", err)
	}

	config := wgtypes.Config{
		PrivateKey: &f.wireguardPrivateKey,
	}

	if err := wgctrlClient.ConfigureDevice(link.Attrs().Name, config); err != nil {
		return fmt.Errorf("configure wireguard interface: %w", err)
	}

	if err := f.netns.AddrAdd(link, &netlink.Addr{IPNet: &f.wireguardAddress}); err != nil {
		return fmt.Errorf("set address: %w", err)
	}

	if err := f.netns.LinkSetUp(link); err != nil {
		return fmt.Errorf("set link up: %w", err)
	}

	if err := f.netns.RouteAdd(&netlink.Route{Dst: f.beehiveIPRange, LinkIndex: link.Index}); err != nil {
		return fmt.Errorf("adding route to bees: %w", err)
	}

	f.wireguard = link
	return nil
}

func (f *Forwarder) setupAttackerCapture(bind netip.Addr) error {
	iface, err := interfaceOfAddress(bind)
	if err != nil {
		return fmt.Errorf("get interface with address: %w", err)
	}
	f.iface = iface

	handle, err := pcap.NewInactiveHandle(iface.Name)
	if err != nil {
		return fmt.Errorf("create inactive handle: %w", err)
	}
	if err := handle.SetImmediateMode(true); err != nil {
		return fmt.Errorf("set immediate mode: %w", err)
	}
	if err := handle.SetTimeout(pcap.BlockForever); err != nil {
		return fmt.Errorf("set timeout: %w", err)
	}
	if err := handle.SetSnapLen(1600); err != nil {
		return fmt.Errorf("set snap length: %w", err)
	}

	attackerCapture, err := handle.Activate()
	if err != nil {
		return fmt.Errorf("activate handle: %w", err)
	}
	if err := attackerCapture.SetBPFFilter(fmt.Sprintf("host %s", bind)); err != nil {
		return fmt.Errorf("set BPF filter: %w", err)
	}
	if err := attackerCapture.SetDirection(pcap.DirectionIn); err != nil {
		return fmt.Errorf("set direction: %w", err)
	}

	f.attackerCapture = attackerCapture

	return nil
}

func (f *Forwarder) setupBeehiveConnection() error {
	beehiveConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: f.wireguardAddress.IP, Port: GenevePort})
	if err != nil {
		return fmt.Errorf("connect to beehive: %w", err)
	}
	f.beehiveConn = beehiveConn
	return nil
}

func (f *Forwarder) setupAttackerInject() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("create raw socket: %w", err)
	}
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, f.iface.Name); err != nil {
		return fmt.Errorf("bind raw socket: %w", err)
	}
	f.attackerInjectFd = fd

	return nil
}

func (f *Forwarder) closeBeehiveConnection() error {
	return f.beehiveConn.Close()
}

func (f *Forwarder) closeWireguard() error {
	if err := f.netns.LinkDel(f.link); err != nil {
		return fmt.Errorf("deleting wireguard link: %w", err)
	}
	return nil
}

func (f *Forwarder) closeNetns() error {
	if f.netnsFd != nil {
		err := f.netnsFd.Close()
		if err != nil {
			return fmt.Errorf("closing netns fd: %w", err)
		}
	}
	return nil
}

// Close cleans up the network setup that was created when creating a new forwarder.
func (f *Forwarder) Close() error {
	if err := f.closeBeehiveConnection(); err != nil {
		return fmt.Errorf("closing beehive connection: %w", err)
	}

	if err := f.closeWireguard(); err != nil {
		return fmt.Errorf("closing wireguard: %w", err)
	}

	if err := f.closeNetns(); err != nil {
		return fmt.Errorf("closing network namespace: %w", err)
	}

	return nil
}
