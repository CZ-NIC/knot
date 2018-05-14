FROM debian:stable-slim
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>

# Select entrypoint
WORKDIR /root
CMD /sbin/knotd & /sbin/knotc

# Expose port
EXPOSE 53/UDP 53/TCP

# Environment
ENV THREADS 4
ENV BUILD_PKGS git-core make gcc libtool autoconf pkg-config liburcu-dev \
               liblmdb-dev libgnutls28-dev libedit-dev libidn11-dev
ENV RUNTIME_PKGS liburcu4 liblmdb0 libgnutls30 libedit2 libidn11

# Install dependencies and sources
RUN apt-get -q -y update && \
apt-get install -q -y ${BUILD_PKGS} ${RUNTIME_PKGS} && \
# Compile sources
git clone -b master https://gitlab.labs.nic.cz/knot/knot-dns.git /knot-src && \
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

# Use example configuration and zone
RUN mv /etc/knot/knot.sample.conf /etc/knot/knot.conf && \
echo '  - domain: example.com\n    file: "/etc/knot/example.com.zone"' >> /etc/knot/knot.conf
