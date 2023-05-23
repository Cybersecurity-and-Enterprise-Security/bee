ARG BUILDER
FROM --platform=$BUILDPLATFORM golang:bullseye AS base

ARG TARGETARCH
ARG TARGETVARIANT

RUN --mount=type=bind,source=build/deps.sh,target=/deps.sh /deps.sh

WORKDIR /workspace
COPY . .
RUN make build

FROM scratch AS binary
COPY --from=base /workspace/bee /

FROM debian:bullseye-slim as bee
# Install libpcap-dev, required for running the binary
RUN apt update && \
    apt install -y libpcap-dev ca-certificates iproute2 wireguard-tools && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/bee

COPY --from=base /workspace/bee /usr/local/bin/bee

WORKDIR /etc/bee
ENTRYPOINT [ "/usr/local/bin/bee" ]
