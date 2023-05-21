FROM golang:bullseye

# Install libpcap-dev, required for building the binary
RUN apt update && \
    apt install -y libpcap-dev && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Install linter
RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.52.0
