package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"gitlab.cyber-threat-intelligence.com/software/alvarium/bee/internal/apibee"
	"gitlab.cyber-threat-intelligence.com/software/alvarium/bee/internal/heartbeat"
	"gitlab.cyber-threat-intelligence.com/software/alvarium/bee/pkg/forward"
)

const loopRestartInterval = 1 * time.Second

func init() {
	log.SetLevel(log.DebugLevel)
}

type arguments struct {
	BindAddress       netip.Addr
	BeekeeperBasePath string
}

func parseArgs() arguments {
	var result arguments
	var bindAddress string

	if os.Getenv("BEE_MODE") == "development" {
		flag.StringVar(&result.BeekeeperBasePath, "beekeeper", "http://localhost:3001/v1", "base path of the beekeeper")
	} else {
		result.BeekeeperBasePath = "https://beekeeper.thebeelab.net/v1"
	}

	flag.StringVar(&bindAddress, "bind", "", "address to bind listener to")
	flag.Parse()

	if bindAddress == "" {
		fmt.Fprintln(os.Stderr, "You need to specify a bind address using -bind.")
		flag.Usage()
		os.Exit(1)
	}

	result.BindAddress = netip.MustParseAddr(bindAddress)
	return result
}

func main() {
	args := parseArgs()

	log.Info("Starting...")

	err := run(args.BindAddress, args.BeekeeperBasePath)
	if err != nil {
		log.WithError(err).Fatal("failed to run")
	}
	log.Info("Quitting...")
}

func run(bindAddress netip.Addr, beekeeperBasePath string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bee, err := startBee(ctx, beekeeperBasePath)
	if err != nil {
		return fmt.Errorf("starting bee failed: %w", err)
	}

	forwarder, err := forward.NewForwarder(bindAddress, bee.WireGuardIP, bee.WireGuardPrivateKey, bee.BeehiveIPRange)
	if err != nil {
		return fmt.Errorf("creating new forwarder: %w", err)
	}
	defer forwarder.Close()

	heartbeat := heartbeat.NewHeartbeat(bee, forwarder, bindAddress)

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			if err := forwarder.AttackerToBeehiveLoop(ctx); err != nil {
				log.WithError(err).Error("Attacker to Beehive loop failed. Restarting.")
			}
			select {
			case <-time.After(loopRestartInterval):
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			if err := forwarder.BeehiveToAttackerLoop(ctx); err != nil {
				log.WithError(err).Error("Beehive to Attacker loop failed. Restarting.")
			}
			select {
			case <-time.After(loopRestartInterval):
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		for {
			if err := heartbeat.Run(ctx); err != nil {
				log.WithError(err).Error("Heartbeat failed. Restarting.")
			}
			select {
			case <-time.After(loopRestartInterval):
			case <-ctx.Done():
				return
			}
		}
	}()

	sig := <-signalChannel
	log.WithField("signal", sig).Info("Received signal, shutting down")

	return nil
}

func startBee(ctx context.Context, beekeeperBasePath string) (*apibee.Bee, error) {
	bee, err := apibee.LoadOrRegisterBee(beekeeperBasePath)
	if err != nil {
		return nil, fmt.Errorf("loading or registering bee: %w", err)
	}

	if err := bee.Startup(ctx); err != nil {
		return nil, fmt.Errorf("starting bee: %w", err)
	}

	name, err := bee.Name(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting bee's name failed: %w", err)
	}

	log.WithField("name", name).Infof("Bee starting")
	return bee, nil
}
