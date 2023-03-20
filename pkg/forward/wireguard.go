package forward

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	IfNameWireguard = "wireguard0"
)

var (
	IPv4MaskOnes = net.IPv4Mask(255, 255, 255, 255)
	// The beehive keeps the wireguard connection to the bees alive (to prevent
	// NAT closing), for the case that a honeypot wants to send out data.
	PersistentKeepaliveInterval = 30 * time.Second
)

type WireguardBeehive struct {
	PublicKey wgtypes.Key
	Address   net.IP
	Endpoint  *net.UDPAddr
}

// UpdateWireguardPeers updates the wireguard peers (bees) of the forwarder.
// The given newPeers replace the old peers, so if a peer should be kept,
// it has to be included in the newPeers.
func (f *Forwarder) UpdateWireguardPeers(newPeers []WireguardBeehive) error {
	if f.wireguard == nil {
		return errors.New("wireguard not set up")
	}

	wgctrlClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("create wgctrl client: %w", err)
	}

	oldConfig, err := wgctrlClient.Device(f.wireguard.Attrs().Name)
	if err != nil {
		return fmt.Errorf("get wireguard config: %w", err)
	}

	diff := diffWireguardPeers(oldConfig.Peers, newPeers)
	newConfig := wgtypes.Config{
		Peers: diff,
	}

	if err := wgctrlClient.ConfigureDevice(f.wireguard.Attrs().Name, newConfig); err != nil {
		return fmt.Errorf("update peers: %w", err)
	}
	return nil
}

// diffWireguardPeers compares oldPeers to newPeers and returns a list of peer configurations
// that represent the difference and can be applied to the interface to get to
// the newPeers.
func diffWireguardPeers(oldPeers []wgtypes.Peer, newPeers []WireguardBeehive) []wgtypes.PeerConfig {
	newPeersIndex := make(map[wgtypes.Key]WireguardBeehive, len(newPeers))
	for _, newPeer := range newPeers {
		newPeersIndex[newPeer.PublicKey] = newPeer
	}

	oldPeersIndex := make(map[wgtypes.Key]wgtypes.Peer, len(oldPeers))
	for _, currentPeer := range oldPeers {
		oldPeersIndex[currentPeer.PublicKey] = currentPeer
	}

	diff := make([]wgtypes.PeerConfig, 0)

	for oldPeerKey, oldPeerConfig := range oldPeersIndex {
		newPeer, ok := newPeersIndex[oldPeerKey]

		if !ok {
			// Peer was removed.
			diff = append(diff, wgtypes.PeerConfig{
				PublicKey: oldPeerKey,
				Remove:    true,
			})
		} else if len(oldPeerConfig.AllowedIPs) == 1 &&
			oldPeerConfig.AllowedIPs[0].IP.Equal(newPeer.Address) &&
			oldPeerConfig.Endpoint != nil && oldPeerConfig.Endpoint.IP.Equal(newPeer.Endpoint.IP) && oldPeerConfig.Endpoint.Port == newPeer.Endpoint.Port {
			// Peer stayed the same.
		} else {
			// Peer changed.
			diff = append(diff, wgtypes.PeerConfig{
				PublicKey:         oldPeerKey,
				UpdateOnly:        true,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{{IP: newPeer.Address, Mask: IPv4MaskOnes}},
				Endpoint:          newPeer.Endpoint,
			})
		}
	}

	for newPeerKey, newPeerConfig := range newPeersIndex {
		_, ok := oldPeersIndex[newPeerKey]
		if !ok {
			// Peer is new.
			diff = append(diff, wgtypes.PeerConfig{
				PublicKey:                   newPeerKey,
				ReplaceAllowedIPs:           true,
				AllowedIPs:                  []net.IPNet{{IP: newPeerConfig.Address, Mask: IPv4MaskOnes}},
				PersistentKeepaliveInterval: &PersistentKeepaliveInterval,
				Endpoint:                    newPeerConfig.Endpoint,
			})
		}
		// The case that the new peer is already in the current peers is already
		// handled by the peer stayed the same and peer changed cases above.
	}

	return diff
}
