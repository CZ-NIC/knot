FROM debian:jessie 
MAINTAINER Marek Vavrusa <marek.vavrusa@nic.cz>

# Nprocs
ENV THREADS 4 

# Install dependencies and sources 
RUN apt-get -y update; \
apt-get install -y \
build-essential \
git-core \
libtool \
autoconf \
flex \
bison \
libssl-dev \
liburcu-dev \
pkg-config \
liblmdb-dev; \
# Fetch sources
mkdir /src; \
git clone https://gitlab.labs.nic.cz/labs/knot.git /src/knot; \
# Compile sources in the right order
cd /src/knot && autoreconf -if && ./configure && make -j${THREADS} && make install && ldconfig; \
# Trim down the image
apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /src

# Select entrypoint
WORKDIR /root
CMD ["/usr/local/sbin/knotd"]

# Expose port
EXPOSE 53
