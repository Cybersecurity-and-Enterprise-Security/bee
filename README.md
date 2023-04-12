# 🐝 bee 🐝

[![pipeline status](https://gitlab.cyber-threat-intelligence.com/software/alvarium/bee/badges/main/pipeline.svg)](https://gitlab.cyber-threat-intelligence.com/software/alvarium/bee/-/commits/main)

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

For now, we **strongly** suggest that you have two interfaces on your machine:
One for your connection via SSH etc. and one for incoming traffic.
If this is not possible for you, the following configuration will work with one interface as well, but you may receive error messages which can be ignored.

**Important**: Adjust `listen_iface` and `ssh_port` accordingly.
If your system only has one network interface, you may loose access to the server if you don't adjust the `ssh_port` properly!
Also, make sure that your endpoint configuration in the frontend blocks your SSH port!

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
1. [Build](#build) the binary locally (recommended) or [get the latest prebuild binary](https://gitlab.cyber-threat-intelligence.com/software/alvarium/bee/-/jobs/artifacts/main/download?job=compile) from the main branch (note that this is currently specifically build for the latest Debian, so it might not work on your local system).
1. Create a new endpoint in the Beekeeper using the frontend or API directly.
1. Copy the registration token.
1. Start the Bee using the following command. Currently, the binary requires elevated privileges because of the network operations. Replace `beekeeperUrl` with the URL of your Beekeeper, e.g. `http://127.0.0.1:3001/v1` and `ipAddress` with the IP address you want the Bee to listen on. Usually, this will be your public facing IP address.

    ```bash
    sudo ./bee -beekeeper <beekeeperUrl> -bind <ipAddress>
    ```

1. Finally, you should be asked to input the registration token copied above.
1. The Bee should now be up and running. Note that it stores relevant data in a `bee.store` file. If that file is lost, you need to reregister the Bee.

## Build

Building the binary requires the libpcap header files, which are part of the `libpcap-dev` package on Debian-based distros.

1. Clone the project.

    ```bash
    git clone --recurse-submodules https://gitlab.cyber-threat-intelligence.com/software/alvarium/bee.git
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
