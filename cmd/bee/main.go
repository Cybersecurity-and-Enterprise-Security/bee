package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"gitlab.cyber-threat-intelligence.com/software/alvarium/bee/internal/apibee"
	"gitlab.cyber-threat-intelligence.com/software/alvarium/bee/pkg/forward"
)

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

	flag.StringVar(&bindAddress, "bind", "", "address to bind listener to")
	flag.StringVar(&result.BeekeeperBasePath, "beekeeper", "http://127.0.0.1:3001/v1", "base path of the beekeeper")
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
	bee, err := startBee(beekeeperBasePath)
	if err != nil {
		return fmt.Errorf("starting bee failed: %w", err)
	}

	forwarder, err := forward.NewForwarder(bindAddress, netip.MustParseAddr(bee.WireGuardIP))
	if err != nil {
		return fmt.Errorf("creating new forwarder: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorChannel := make(chan error, 1)
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := forwarder.AttackerToBeehiveLoop(ctx); err != nil {
			errorChannel <- err
		}
	}()

	go func() {
		if err := forwarder.BeehiveToAttackerLoop(ctx); err != nil {
			errorChannel <- err
		}
	}()

	go func() {
		if err := bee.Heartbeat(ctx); err != nil {
			errorChannel <- err
		}
	}()

	select {
	case <-signalChannel:
	case err := <-errorChannel:
		return fmt.Errorf("forward: %w", err)
	}

	return nil
}

func startBee(beekeeperBasePath string) (*apibee.Bee, error) {
	bee, err := apibee.LoadOrRegisterBee(beekeeperBasePath)
	if err != nil {
		return nil, fmt.Errorf("starting bee: %w", err)
	}

	name, err := bee.Name()
	if err != nil {
		return nil, fmt.Errorf("getting bee's name failed: %w", err)
	}

	log.WithField("name", name).Infof("Bee starting")
	return bee, nil
}
