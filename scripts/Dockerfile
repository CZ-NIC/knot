FROM debian:jessie
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>

# Select entrypoint
WORKDIR /root
CMD ["/usr/local/sbin/knotd"]

# Expose port
EXPOSE 53

# Environment
ENV THREADS 4
ENV BUILD_PKGS git-core make gcc libtool autoconf pkg-config \
               liburcu-dev liblmdb-dev libgnutls28-dev libjansson-dev libedit-dev libidn11-dev
ENV RUNTIME_PKGS liburcu2 liblmdb0 libgnutls-deb0-28 libjansson4 libedit2 libidn11

# Install dependencies and sources
RUN apt-get -q -y update && \
apt-get install -q -y ${BUILD_PKGS} ${RUNTIME_PKGS} && \
# Compile sources
git clone -b master https://gitlab.labs.nic.cz/labs/knot.git /knot-src && \
cd /knot-src && \
autoreconf -if && \
./configure --disable-static --enable-fastparser --disable-documentation && \
make -j${THREADS} && \
make install && \
ldconfig && \
# Trim down the image
cd && \
rm -rf /knot-src && \
apt-get purge -q -y ${BUILD_PKGS} && \
apt-get autoremove -q -y && \
apt-get clean && \
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
