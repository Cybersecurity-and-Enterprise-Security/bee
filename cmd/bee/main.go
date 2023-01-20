package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	BindAddress       string
	BeehiveAddress    string
	BeekeeperBasePath string
}

func parseArgs() arguments {
	var result arguments
	flag.StringVar(&result.BindAddress, "bind", "", "address to bind listener to")
	flag.StringVar(&result.BeehiveAddress, "beehive", "127.0.0.1:8335", "address of the beehive")
	flag.StringVar(&result.BeekeeperBasePath, "beekeeper", "http://127.0.0.1:3001/v1", "base path of the beekeeper")
	flag.Parse()

	if result.BindAddress == "" {
		fmt.Fprintln(os.Stderr, "You need to specify a bind address using -bind.")
		flag.Usage()
		os.Exit(1)
	}
	return result
}

func main() {
	args := parseArgs()

	log.Info("Starting...")

	err := run(args.BindAddress, args.BeehiveAddress, args.BeekeeperBasePath)
	if err != nil {
		log.WithError(err).Fatal("failed to run")
	}
	log.Info("Quitting...")
}

func run(bindAddress string, beehiveAddress string, beekeeperBasePath string) error {
	bee, err := startBee(beekeeperBasePath)
	if err != nil {
		return fmt.Errorf("starting bee failed: %w", err)
	}

	forwarder, err := forward.NewForwarder(bindAddress, beehiveAddress)
	if err != nil {
		return fmt.Errorf("creating new forwarder: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorChannel := make(chan error, 1)
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := forwarder.Forward(ctx); err != nil {
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
	bee, err := apibee.NewBee(beekeeperBasePath)
	if err != nil {
		return nil, fmt.Errorf("creating new bee: %w", err)
	}

	if err := bee.LoadFromFile(); err != nil {
		if errors.Is(err, apibee.ErrBeeConfigNotFound) {
			log.Info("No existing bee config found")

			var registrationToken string
			fmt.Println("\nRegistering new endpoint. Please enter registration token: ")
			if _, err := fmt.Scanln(&registrationToken); err != nil {
				return nil, fmt.Errorf("reading registration token failed: %w", err)
			}

			if err := bee.Register(registrationToken); err != nil {
				return nil, fmt.Errorf("registering bee failed: %w", err)
			}

			if err := bee.StoreToFile(); err != nil {
				return nil, fmt.Errorf("storing bee to faile failed: %w", err)
			}
		}
	}

	name, err := bee.Name()
	if err != nil {
		return nil, fmt.Errorf("getting bee's name failed: %w", err)
	}

	log.WithField("name", name).Infof("Bee starting")
	return bee, nil
}
