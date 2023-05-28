package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Cybersecurity-and-Enterprise-Security/bee/internal/apibee"
	"github.com/Cybersecurity-and-Enterprise-Security/bee/internal/heartbeat"
	"github.com/Cybersecurity-and-Enterprise-Security/bee/pkg/forward"
	log "github.com/sirupsen/logrus"
)

const loopRestartInterval = 1 * time.Second

func init() {
	log.SetLevel(log.DebugLevel)
}

func main() {
	args := parseArgs()

	log.WithField("BindAddress", args.BindAddress).Info("Starting Bee")

	err := run(args.BindAddress, args.BeekeeperBasePath)
	if err != nil {
		log.WithError(err).Fatal("failed to run")
	}
	log.Info("Quitting...")
}

func recoverPanic(signalChannel chan os.Signal) {
	if err := recover(); err != nil {
		log.WithField("panic", err).Error("panic occurred, shutting down")
		close(signalChannel)
	}
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

	defer recoverPanic(signalChannel)

	go func() {
		defer recoverPanic(signalChannel)
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
		defer recoverPanic(signalChannel)
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
		defer recoverPanic(signalChannel)
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
