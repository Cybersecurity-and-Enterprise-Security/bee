package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type arguments struct {
	BindAddress       netip.Addr
	BeekeeperBasePath string
	LogLevel          logrus.Level
	DisableNftables   bool
}

func parseArgs() arguments {
	var result arguments
	var bindAddress, loglevel string

	if os.Getenv("BEE_MODE") == "development" {
		flag.StringVar(&result.BeekeeperBasePath, "beekeeper", "http://localhost:3001/v1", "base path of the beekeeper")
	} else {
		result.BeekeeperBasePath = "https://beekeeper.thebeelab.net/v1"
	}

	flag.StringVar(&loglevel, "loglevel", "info", "log level to use. See https://github.com/sirupsen/logrus#level-logging for available levels.")
	flag.StringVar(&bindAddress, "bind", "", "address to bind listener to")
	flag.BoolVar(&result.DisableNftables, "disableNftables", false, "disable automatic configuration of nftables")
	flag.Parse()

	if bindAddress == "" {
		defaultAddress, err := defaultListenIP()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Getting default listen IP failed: %v\n", err)
			fmt.Fprintln(os.Stderr, "You need to specify a bind address using -bind.")
			flag.Usage()
			os.Exit(1)
		}
		bindAddress = defaultAddress
	}
	result.BindAddress = netip.MustParseAddr(bindAddress)

	logrusLevel, err := logrus.ParseLevel(loglevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid loglevel: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}
	result.LogLevel = logrusLevel

	return result
}

func defaultListenIP() (string, error) {
	routes, err := netlink.RouteGet(net.ParseIP("1.1.1.1"))
	if err != nil {
		return "", fmt.Errorf("getting route to 1.1.1.1: %w", err)
	}

	if len(routes) == 0 {
		return "", fmt.Errorf("no default route found")
	}

	return routes[0].Src.String(), nil
}
