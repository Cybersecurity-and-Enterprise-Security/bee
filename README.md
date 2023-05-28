# 🐝 bee 🐝

[![Run Tests](https://github.com/Cybersecurity-and-Enterprise-Security/bee/actions/workflows/test.yaml/badge.svg)](https://github.com/Cybersecurity-and-Enterprise-Security/bee/actions/workflows/test.yaml)
[![Docker](https://github.com/Cybersecurity-and-Enterprise-Security/bee/actions/workflows/docker.yaml/badge.svg)](https://github.com/Cybersecurity-and-Enterprise-Security/bee/actions/workflows/docker.yaml)

The bee is the public facing endpoint in the Alvarium honeypot project.

It can:

- Register itself with the Beekeeper using a registration token
- Periodically send statistics as a heartbeat to the Beekeeper
- Connect to Beehives automatically via WireGuard when needed
- Read packets from the specified interface and forward them to the respective Beehive according to the currently active forwarding rules

## Requirements

Right now, a Linux system like Ubuntu or Debian is required.
We might extend the program to Windows and others in the future.

Because we need to drop the Kernel responses to incoming traffic (to avoid that the Kernel sends RST packets for closed ports), please make sure, that an nftables policy like this is applied.

**Important**: Adjust `listen_iface` and `ssh_port` accordingly.
If your system only has one network interface, you may loose access to the server if you don't adjust the `ssh_port` properly!

Also, make sure that your endpoint configuration in the frontend blocks your SSH port!
If you registered the device via the stepper in the tarpit, this is done for you already.

```conf
#!/usr/sbin/nft -f

flush ruleset

define listen_iface = ens19
define ssh_port = 22

table inet filter {
        chain input {
                type filter hook input priority filter;
                iifname $listen_iface jump forwarder_block
        }
        chain forward {
                type filter hook forward priority filter;
        }
        chain output {
                type filter hook output priority filter;
        }

        chain forwarder_block {
                ct state {established, related} accept
                tcp dport $ssh_port accept

                meta l4proto {icmp, tcp, udp} drop
        }
}
```

## Usage

1. Make sure the [requirements](#requirements) for running the Bee are met on your system.
1. Create a new endpoint in the Beekeeper using the frontend or API directly.
1. Copy the registration token.

### Docker (recommended)

1. Make sure that your machine has `docker` and `docker-compose` installed.
1. Copy the [docker-compose.yaml](./docker-compose.yaml) to your machine.
1. Adjust the `-bind` argument accordingly to your setup. Usually, this will be the IP of your public-facing interface (the one with the default route).
1. Set the `BEE_REGISTRATION_TOKEN` environment variable to the value you copied above.
1. Start the container

    ```bash
    docker compose up -d
    ```

### Binary

1. Do one of the following to get your binary.
        - Get the latest prebuild binary for your architecture from the [releases](https://github.com/Cybersecurity-and-Enterprise-Security/bee/releases) (note that this is currently specifically build for the latest Debian, so it might not work on your local system).
        - [Build](#build) the binary locally.
1. Currently, the binary requires elevated privileges because of the network operations. Hence, either run the binary with `sudo`, or set the necessary capabilities using `sudo setcap cap_net_admin,cap_net_raw=eip ./bee`. Replace `ipAddress` with the IP address you want the Bee to listen on. Usually, this will be your public facing IP address.

    ```bash
    sudo ./bee -bind <ipAddress>
    ```

1. Finally, you should be asked to input the registration token copied above.
1. The Bee should now be up and running. Note that it stores relevant data in a `bee.store` file. If that file is lost, you need to reregister the Bee.

## Build

1. Building the binary requires the libpcap header files, which are part of the `libpcap-dev` package on Debian-based distros. Adjust the command according to your package manager.

    ```bash
    sudo apt install libpcap-dev
    ```

1. Clone the project.

    ```bash
    git clone --recurse-submodules git@github.com:Cybersecurity-and-Enterprise-Security/bee.git
    cd bee
    ```

1. Install dependencies.

    ```bash
    make generate-deps
    ```

1. Make sure that the `bin` folder of your Go installation is part of your `PATH`, e.g. `export PATH+=:~/go/bin`.
1. Build the binary.

    ```bash
    make build
    ```
