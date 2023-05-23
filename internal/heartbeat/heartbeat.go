package heartbeat

import (
	"context"
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

func NewHeartbeat(bee *apibee.Bee, forwarder *forward.Forwarder, bindAddress netip.Addr) *Heartbeat {
	return &Heartbeat{
		bee,
		forwarder,
		bindAddress,
	}
}

func (h *Heartbeat) Run(ctx context.Context) error {
	for {
		h.ReportStats(ctx)
		h.UpdateForwardings(ctx)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(heartbeatInterval):
		}
	}
}

func (h *Heartbeat) ReportStats(ctx context.Context) {
	if err := h.bee.ReportStatistics(ctx, h.bindAddress.String()); err != nil {
		log.WithError(err).Warn("Error during heartbeat")
	}
}

func (h *Heartbeat) UpdateForwardings(ctx context.Context) {
	info, err := h.bee.GetForwardingInformation(ctx)
	if err != nil {
		log.WithError(err).Error("Error getting forwarding information")
		return
	}

	h.forwarder.SetDefaultBeehiveAddress(info.DefaultBeehive)
	log.WithField("beehive", info.DefaultBeehive).Debug("updated default beehive")

	newBeehives := make([]forward.WireguardBeehive, 0, len(info.Beehives))
	for _, beehive := range info.Beehives {
		log := log.WithField("beehive", beehive)

		log.Debug("Got beehive")

		publicKey, err := wgtypes.ParseKey(beehive.PublicKey)
		if err != nil {
			log.WithError(err).Error("Parsing public key")
			continue
		}
		address := net.ParseIP(beehive.Ip)
		if address == nil {
			log.Error("Error parsing IP")
			continue
		}

		endpoint, err := netip.ParseAddrPort(beehive.Endpoint)
		if err != nil {
			log.WithError(err).Error("Parsing endpoint addr port")
			continue
		}

		newBeehives = append(newBeehives, forward.WireguardBeehive{
			PublicKey: publicKey,
			Address:   address,
			Endpoint:  net.UDPAddrFromAddrPort(endpoint),
		})
	}

	if err := h.forwarder.UpdateWireguardPeers(newBeehives); err != nil {
		log.WithError(err).Error("updating wireguard peers")
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
}
