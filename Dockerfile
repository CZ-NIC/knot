## Intermediate stage ##
FROM debian:bullseye-slim

# Environment
ENV BUILD_PKGS \
    autoconf \
    automake \
    gcc \
    libbpf-dev \
    libedit-dev \
    libelf-dev \
    libfstrm-dev \
    libgnutls28-dev \
    libidn2-0-dev \
    liblmdb-dev \
    libmaxminddb-dev \
    libmnl-dev \
    libnghttp2-dev \
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
COPY . /knot-src
WORKDIR /knot-src
RUN autoreconf -if && \
    ./configure --prefix=/ \
                --with-rundir=/rundir \
                --with-storage=/storage \
                --with-configdir=/config \
                --with-module-dnstap=yes \
                --disable-fastparser \
                --disable-static \
                --disable-documentation && \
    make -j$(grep -c ^processor /proc/cpuinfo) && \
    make install DESTDIR=/tmp/knot-install

## Final stage ##
FROM debian:bullseye-slim
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>

# Environment
ENV RUNTIME_PKGS \
    libbpf0 \
    libedit2 \
    libelf1 \
    libfstrm0 \
    libgnutls30 \
    libidn2-0 \
    liblmdb0 \
    libmaxminddb0 \
    libmnl0 \
    libnghttp2-14 \
    libprotobuf-c1 \
    liburcu6

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
