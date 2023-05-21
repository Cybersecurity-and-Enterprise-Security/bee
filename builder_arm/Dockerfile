FROM golang:bullseye

# Install dependencies for cross compilation
RUN apt update && \
    apt install -y libpcap-dev gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu flex bison && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

ENV PCAPV=1.10.4
ENV PCAP_SRC=/usr/local/include/libpcap-$PCAPV
ENV PCAP_SRC_ARM=${PCAP_SRC}-arm
ENV PCAP_SRC_AARCH64=${PCAP_SRC}-aarch64

RUN cd /tmp && \
    wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz && \
    tar xvf libpcap-$PCAPV.tar.gz && \
    rm libpcap-$PCAPV.tar.gz && \
    cp -r libpcap-$PCAPV ${PCAP_SRC_ARM} && \
    cp -r libpcap-$PCAPV ${PCAP_SRC_AARCH64}

# Build for ARM
RUN cd $PCAP_SRC_ARM && \
    export CC=arm-linux-gnueabi-gcc && \
    ./configure --host=arm-linux --with-pcap=linux && \
    make

# Build for AArch64
RUN cd $PCAP_SRC_AARCH64 && \
    export CC=aarch64-linux-gnu-gcc && \
    ./configure --host=aarch64-linux --with-pcap=linux && \
    make
