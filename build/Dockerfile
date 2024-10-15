# This image is used to build the binary for different architectures.
FROM --platform=$BUILDPLATFORM golang:bookworm AS base

ARG TARGETARCH
ARG TARGETVARIANT

ENV DEBIAN_FRONTEND=noninteractive

RUN --mount=type=bind,source=build/deps.sh,target=/deps.sh /deps.sh

WORKDIR /workspace
COPY . .
RUN make build

# This image is used for the artifacts in the GitHub pipeline.
FROM scratch AS binary
COPY --from=base /workspace/bee /

# This image is meant for running the bee.
FROM debian:bookworm-slim AS bee

# Install runtime dependencies of the binary.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && \
    apt install -y libpcap-dev ca-certificates iproute2 wireguard-tools nftables && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/bee

COPY --from=base /workspace/bee /usr/local/bin/bee

WORKDIR /etc/bee
ENTRYPOINT [ "/usr/local/bin/bee" ]
