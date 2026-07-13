FROM kathara/base

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        git \
        ca-certificates \
        iproute2 \
        net-tools && \
    rm -rf /var/lib/apt/lists/* && \
    git clone --depth 1 https://github.com/noxrepo/pox.git /pox

WORKDIR /pox
