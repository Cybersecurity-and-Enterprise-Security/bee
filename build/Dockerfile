FROM --platform=$BUILDPLATFORM debian:bullseye-slim

# Install libpcap-dev, required for running the binary
RUN apt update && \
    apt install -y libpcap-dev ca-certificates && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/bee

ARG BEE_PATH=./bee
COPY ${BEE_PATH} /bin/bee

WORKDIR /etc/bee
ENTRYPOINT [ "/bin/bee" ]
