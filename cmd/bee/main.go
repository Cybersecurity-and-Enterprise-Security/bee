package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"gitlab.cyber-threat-intelligence.com/software/alvarium/bee/pkg/forward"
)

type arguments struct {
	BindAddress    string
	BeehiveAddress string
}

func parseArgs() arguments {
	var result arguments
	flag.StringVar(&result.BindAddress, "bind", "", "address to bind listener to")
	flag.StringVar(&result.BeehiveAddress, "beehive", "127.0.0.1:1337", "address of the beehive")
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
	err := run(args.BindAddress, args.BeehiveAddress)
	if err != nil {
		log.WithError(err).Fatal("failed to start")
	}
	log.Info("Quitting...")
}

func run(bindAddress string, beehiveAddress string) error {
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

	select {
	case <-signalChannel:
	case err := <-errorChannel:
		return fmt.Errorf("forward: %w", err)
	}

	return nil
}
