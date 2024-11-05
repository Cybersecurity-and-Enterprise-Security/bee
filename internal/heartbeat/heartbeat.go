package heartbeat

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/Cybersecurity-and-Enterprise-Security/bee/internal/apibee"
	"github.com/Cybersecurity-and-Enterprise-Security/bee/pkg/api"
	"github.com/Cybersecurity-and-Enterprise-Security/bee/pkg/forward"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	heartbeatInterval = 1 * time.Minute
)

type Heartbeat struct {
	bee         *apibee.Bee
	forwarder   *forward.Forwarder
	bindAddress netip.Addr
}

func NewHeartbeat(ctx context.Context, bee *apibee.Bee, forwarder *forward.Forwarder, bindAddress netip.Addr) (*Heartbeat, error) {
	heartbeat := &Heartbeat{
		bee,
		forwarder,
		bindAddress,
	}

	// updateForwardings fetches necessary information for the forwarder from the beekeeper.
	if err := heartbeat.updateForwardings(ctx); err != nil {
		return nil, fmt.Errorf("initializing heartbeat: %w", err)
	}

	return heartbeat, nil
}

func (h *Heartbeat) Run(ctx context.Context) error {
	for {
		if err := h.reportStats(ctx); err != nil {
			return fmt.Errorf("reporting stats: %w", err)
		}
		if err := h.updateForwardings(ctx); err != nil {
			return fmt.Errorf("updating forwardings: %w", err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(heartbeatInterval):
		}
	}
}

func (h *Heartbeat) reportStats(ctx context.Context) error {
	if err := h.bee.ReportStatistics(ctx, h.bindAddress.String()); err != nil {
		return fmt.Errorf("contacting beekeeper: %w", err)
	}
	return nil
}

func (h *Heartbeat) updateForwardings(ctx context.Context) error {
	info, err := h.bee.GetForwardingInformation(ctx)
	if err != nil {
		return fmt.Errorf("getting forwarding information: %w", err)
	}

	err = h.forwarder.SetDefaultBeehiveAddress(info.DefaultBeehive)
	if err != nil {
		return fmt.Errorf("updating default beehive address: %w", err)
	} else {
		log.WithField("beehive", info.DefaultBeehive).Debug("Updated default beehive")
	}

	// Errors are only logged here because some beehives may be operational.
	newBeehives := make([]forward.WireguardBeehive, 0, len(info.Beehives))
	for _, beehive := range info.Beehives {
		log := log.WithField("beehive", beehive)

		log.Debug("Got beehive")

		publicKey, err := wgtypes.ParseKey(beehive.PublicKey)
		if err != nil {
			log.WithError(err).Error("Parsing public key")
			continue
		}
		wireguardIp := net.ParseIP(beehive.Ip)
		if wireguardIp == nil {
			log.Error("Error parsing wireguard IP of beehive")
			continue
		}

		endpoint, err := netip.ParseAddrPort(beehive.Endpoint)
		if err != nil {
			log.WithError(err).Error("Parsing endpoint addr port")
			continue
		}

		newBeehives = append(newBeehives, forward.WireguardBeehive{
			PublicKey:   publicKey,
			WireguardIp: wireguardIp,
			Endpoint:    net.UDPAddrFromAddrPort(endpoint),
		})
	}

	if err := h.forwarder.UpdateWireguardPeers(newBeehives); err != nil {
		return fmt.Errorf("updating wireguard peers: %w", err)
	}

	newForwardingRules := make([]forward.ForwardingRule, 0, len(info.Forwardings))
	for _, rule := range info.Forwardings {
		var protocol forward.ForwardingProtocol
		switch rule.Matcher.Protocol {
		case api.Tcp:
			protocol = forward.ForwardingProtocolTCP
		case api.Udp:
			protocol = forward.ForwardingProtocolUDP
		default:
			log.WithField("rule", rule).Error("Unknown forwarding protocol")
			continue
		}

		newForwardingRules = append(newForwardingRules, forward.ForwardingRule{
			Port:           rule.Matcher.Port,
			Protocol:       protocol,
			BeehiveAddress: rule.BeehiveIP,
		})
	}

	h.forwarder.UpdateForwardingRules(newForwardingRules)

	return nil
}
