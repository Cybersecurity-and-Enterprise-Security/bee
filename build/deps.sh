#!/bin/bash

set -e

case "${TARGETARCH}${TARGETVARIANT}" in
    amd64)
        export PACKAGES="libpcap-dev" ;;
    arm64)
        export DPKG_ARCHITECTURE="arm64"
        export PACKAGES="gcc-aarch64-linux-gnu libpcap-dev:arm64" ;;
    armv6)
        export DPKG_ARCHITECTURE="armel"
        export PACKAGES="gcc-arm-linux-gnueabi libpcap-dev:armel" ;;
    armv7)
        export DPKG_ARCHITECTURE="armhf"
        export PACKAGES="gcc-arm-linux-gnueabihf libpcap-dev:armhf" ;;
esac
if [ -n "$DPKG_ARCHITECTURE" ]; then
    dpkg --add-architecture "$DPKG_ARCHITECTURE"
fi
apt update
apt install -y $PACKAGES
apt clean
rm -rf /var/lib/apt/lists/*
