FROM golang:latest

# Install libpcap-dev, required for building the binary
RUN apt update && \
    apt install -y libpcap-dev && \
    apt install -y gcc-arm-linux-gnueabi && \
    apt install -y flex && \
    apt install -y bison && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

ENV PCAPV=1.10.4
ENV PCAP_SRC=/usr/local/include/libpcap-$PCAPV

RUN cd /tmp && \
    wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz && \
    tar xvf libpcap-$PCAPV.tar.gz && \
    rm libpcap-$PCAPV.tar.gz && \
    mv libpcap-$PCAPV $PCAP_SRC && \
    cd $PCAP_SRC && \
    export CC=arm-linux-gnueabi-gcc && \
    ./configure --host=arm-linux --with-pcap=linux && \
    make
