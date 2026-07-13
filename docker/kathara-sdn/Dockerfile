FROM kathara/base

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openvswitch-switch \
        iproute2 \
        net-tools \
        tcpdump && \
    rm -rf /var/lib/apt/lists/*
