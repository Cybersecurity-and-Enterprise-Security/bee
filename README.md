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

Because we need to drop the Kernel responses to incoming traffic (to avoid that the Kernel sends RST packets for closed ports), we apply [an nftables](internal/nftables/bee-nftables.conf) configuration automatically.
Open ports are excluded from the rules to avoid that running services like SSH are blocked.

**Note**: We currently only support nftables.
If your system is using legacy iptables (not `iptables-nft`), disable automatic nftables generation using the `-disableNftables` flag.
Then, please make sure that you apply proper iptables rules, similar to [the nftables rules](internal/nftables/bee-nftables.conf) the program would apply.

Also, make sure that your endpoint configuration in the frontend blocks your open ports!

## Usage

1. Make sure the [requirements](#requirements) for running the Bee are met on your system.
1. Create a new endpoint in the Beekeeper using the frontend or API directly.
1. Copy the registration token.
1. **Note**: Both versions (Docker and binary) choose an IP address to bind to by default [based on your default routes](cmd/bee/args.go). Usually, this should be correct. If your host retrieves the external traffic on a separate IP address, adjust it using the `-bind <ipAddress>` flag.
1. If you do not want to forward specific ports, e.g. if you need **SSH access** to the bee via its bound ip, use the `-ignoredTcpPorts` and `-ignoredUdpPorts` command line arguments. These are comma-separated lists of port ranges, where each range is only one port or `start-end`, e.g. `1-1023,2222`.
    In addition to these, the bee looks for listening sockets on the address at startup and does not forward these. You can see the ignored ports in the log output at startup.

**IF YOUR PRIMARY ACCESS TO THE MACHINE IS THROUGH THE BOUND ADDRESS, DOUBLE-CHECK THAT `-ignoredTcpPorts` INCLUDES ALL PORTS YOU NEED FOR ACCESS. YOU MIGHT BE LOCKED OUT OTHERWISE.**

### Docker (recommended)

1. Make sure that your machine has `docker` with its `compose` plugin installed.
1. Copy the [compose.yaml](./compose.yaml) to your machine.
1. If you need to adjust one of the flags described above, do so with the `command` field in the compose file (the entrypoint of the Docker image is set to the binary).
1. Set the `BEE_REGISTRATION_TOKEN` environment variable to the value you copied above.
1. Start the container

    ```bash
    docker compose up -d
    ```

### Binary

1. Make sure your system has `nftables` installed, since the program uses the `nft` tool.
1. Do one of the following to get your binary.
    - Get the latest prebuild binary for your architecture from the [releases](https://github.com/Cybersecurity-and-Enterprise-Security/bee/releases) (note that this is currently specifically build for the latest Debian, so it might not work on your local system).
    - [Build](#build) the binary locally.
1. Currently, the binary requires elevated privileges because of the network operations. Hence, either run the binary with `sudo`, or set the necessary capabilities using `sudo setcap cap_net_admin,cap_net_raw=eip ./bee`. Remember to also set the flags described above if needed.

    ```bash
    sudo ./bee
    ```

1. Finally, you should be asked to input the registration token copied above.
1. The Bee should now be up and running. Note that it stores relevant data in a `bee.store` file. If that file is lost, you need to reregister the Bee.

## Build

1. Go must be installed on the machine. Please follow [this instruction](https://go.dev/doc/install) from the official Go website to install the latest version.

1. Make sure that the `bin` folder of your Go installation is part of your `PATH`, e.g. `export PATH+=:~/go/bin`.

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

1. Build the binary.

    ```bash
    make build
    ```
