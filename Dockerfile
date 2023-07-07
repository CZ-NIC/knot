## Intermediate stage ##
FROM debian:bookworm-slim AS builder

# Environment
ENV BUILD_PKGS \
    autoconf \
    automake \
    gcc \
    libbpf-dev \
    libedit-dev \
    libfstrm-dev \
    libgnutls28-dev \
    libidn2-0-dev \
    liblmdb-dev \
    libmaxminddb-dev \
    libmnl-dev \
    libnghttp2-dev \
    libngtcp2-crypto-gnutls-dev \
    libngtcp2-dev \
    libprotobuf-c-dev \
    libtool \
    liburcu-dev \
    libxdp-dev \
    make \
    pkg-config \
    protobuf-c-compiler

# Install dependencies
RUN apt-get update && \
    apt-get install -yqq ${BUILD_PKGS}

# Build the project
COPY . /knot-src
WORKDIR /knot-src
ARG FASTPARSER=disable
RUN autoreconf -if && \
    CFLAGS="-g -O2 -DNDEBUG -D_FORTIFY_SOURCE=2 -fstack-protector-strong" \
    ./configure --prefix=/ \
                --with-rundir=/rundir \
                --with-storage=/storage \
                --with-configdir=/config \
                --with-module-dnstap=yes \
                --${FASTPARSER}-fastparser \
                --enable-quic \
                --enable-dnstap \
                --disable-static \
                --disable-documentation && \
    make -j$(grep -c ^processor /proc/cpuinfo)

# Run unittests if requested and install the project
ARG CHECK=disable
RUN if [ "$CHECK" = "enable" ]; then make -j$(grep -c ^processor /proc/cpuinfo) check; fi && \
    make install DESTDIR=/tmp/knot-install

## Final stage ##
FROM debian:bookworm-slim
LABEL maintainer="Knot DNS <knot-dns@labs.nic.cz>"

# Environment
ENV RUNTIME_PKGS \
    libbpf1 \
    libedit2 \
    libfstrm0 \
    libgnutls30 \
    libidn2-0 \
    liblmdb0 \
    libmaxminddb0 \
    libmnl0 \
    libnghttp2-14 \
    libngtcp2-crypto-gnutls2 \
    libngtcp2-9 \
    libprotobuf-c1 \
    liburcu8 \
    libxdp1

# Install dependencies and create knot user and group
ARG UID=53
RUN apt-get update && \
    apt-get install -yqq ${RUNTIME_PKGS} adduser && \
    rm -rf /var/lib/apt/lists/* && \
    ldconfig && \
    adduser --quiet --system --group --no-create-home --home /storage --uid=${UID} knot && \
    install -o knot -g knot -d /config /rundir /storage

# Copy artifacts
# `COPY --from=builder /tmp/knot-install/ /` doesn't work with DOCKER_BUILDKIT=1 under buildx
COPY --from=builder /tmp/knot-install/bin/     /bin/
COPY --from=builder /tmp/knot-install/config/  /config/
COPY --from=builder /tmp/knot-install/include/ /include/
COPY --from=builder /tmp/knot-install/lib/     /lib/
COPY --from=builder /tmp/knot-install/sbin/    /sbin/
COPY --from=builder /tmp/knot-install/share/   /share/

# Expose port
EXPOSE 53/UDP
EXPOSE 53/TCP
EXPOSE 853/UDP

# Prepare shared directories
VOLUME /config
VOLUME /rundir
VOLUME /storage
