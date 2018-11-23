## Intermediate stage ##
FROM debian:stable-slim

# Environment
ENV BUILD_PKGS \
    autoconf \
    automake \
    gcc \
    git-core \
    libedit-dev \
    libfstrm-dev \
    libgnutls28-dev \
    libidn2-0-dev \
    liblmdb-dev \
    libmaxminddb-dev \
    libprotobuf-c-dev \
    libtool \
    liburcu-dev \
    make \
    pkg-config \
    protobuf-c-compiler

# Install dependencies
RUN apt-get update && \
    apt-get install -yqq ${BUILD_PKGS}

# Build the project
ARG BRANCH=master
WORKDIR /knot-src
RUN git clone --depth 1 -b ${BRANCH} https://gitlab.labs.nic.cz/knot/knot-dns.git /knot-src && \
    autoreconf -if && \
    ./configure --prefix=/tmp/knot-install \
                --with-rundir=/rundir \
                --with-storage=/storage \
                --with-configdir=/config \
                --with-module-dnstap=yes \
                --disable-fastparser \
                --disable-static \
                --disable-documentation && \
    make -j$(grep -c ^processor /proc/cpuinfo) && \
    make install

## Final stage ##
FROM debian:stable-slim
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>

# Environment
ENV RUNTIME_PKGS \
    libedit2 \
    libfstrm0 \
    libgnutls30 \
    libidn2-0 \
    liblmdb0 \
    libmaxminddb0 \
    libprotobuf-c1 \
    liburcu4

# Copy artifacts
COPY --from=0 /tmp/knot-install/ /

# Install dependencies
RUN apt-get update && \
    apt-get install -yqq ${RUNTIME_PKGS} && \
    rm -rf /var/lib/apt/lists/* && \
    ldconfig

# Expose port
EXPOSE 53/UDP
EXPOSE 53/TCP

# Prepare shared directories
VOLUME /config
VOLUME /rundir
VOLUME /storage
