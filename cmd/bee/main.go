package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Cybersecurity-and-Enterprise-Security/bee/internal/apibee"
	"github.com/Cybersecurity-and-Enterprise-Security/bee/internal/heartbeat"
	"github.com/Cybersecurity-and-Enterprise-Security/bee/internal/nftables"
	"github.com/Cybersecurity-and-Enterprise-Security/bee/pkg/forward"
	log "github.com/sirupsen/logrus"
)

const loopRestartInterval = 1 * time.Second

func main() {
	args := parseArgs()
	log.SetLevel(args.LogLevel)

	log.WithField("BindAddress", args.BindAddress).Info("Starting bee...")

	err := run(args)
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

func run(args arguments) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bee, err := startBee(ctx, args.BeekeeperBasePath)
	if err != nil {
		return fmt.Errorf("starting bee failed: %w", err)
	}

	if !args.DisableNftables {
		err = nftables.ConfigureNftables(args.BindAddress, args.IgnoredTCPPorts, args.IgnoredUDPPorts)
		if err != nil {
			return fmt.Errorf("configuring nftables: %w", err)
		}
		defer func() {
			if err := nftables.RemoveNftables(); err != nil {
				log.WithError(err).Error("Removing nftables failed. You may need to remove the rules in the bee_filter table manually.")
			}
		}()
	}

	forwarder, err := forward.NewForwarder(args.BindAddress, bee.WireGuardIP, bee.WireGuardPrivateKey, bee.BeehiveIPRange)
	if err != nil {
		return fmt.Errorf("creating new forwarder: %w", err)
	}
	defer forwarder.Close()

	heartbeat, err := heartbeat.NewHeartbeat(ctx, bee, forwarder, args.BindAddress)
	if err != nil {
		return fmt.Errorf("creating heartbeat service: %w", err)
	}

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

	log.Info("Bee startup complete")

	sig, ok := <-signalChannel
	if ok {
		log.WithField("signal", sig).Info("Received signal, shutting down")
	}

	return nil
}

func startBee(ctx context.Context, beekeeperBasePath string) (*apibee.Bee, error) {
	bee, err := apibee.LoadOrRegisterBee(beekeeperBasePath)
	if err != nil {
		return nil, fmt.Errorf("loading or registering bee: %w", err)
	}

	if err := bee.Startup(ctx); err != nil {
		return nil, fmt.Errorf("reporting startup: %w", err)
	}

	name, err := bee.Name(ctx)
	if err != nil {
		return nil, fmt.Errorf("requesting name: %w", err)
	}
	log.WithField("name", name).Infof("Bee name was retrieved successfully")

	return bee, nil
}
