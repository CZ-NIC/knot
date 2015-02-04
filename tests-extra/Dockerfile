FROM cznic/knot:latest
MAINTAINER Marek Vavrusa <marek.vavrusa@nic.cz>

# Environment
ENV RUNTIME_PKGS gawk python3 python3-pip bind9 bind9utils valgrind lsof gdb

# Copy test cases
COPY . /knot-src/tests-extra

# Select entrypoint
WORKDIR /knot-src/tests-extra
ENTRYPOINT ["/knot-src/tests-extra/runtests.py"]

# Install dependencies and sources
RUN apt-get -q -y update && \
apt-get install -q -y ${RUNTIME_PKGS} && \
pip3 install -r /knot-src/tests-extra/requirements.txt && \
# Link the prebuilt executables
mkdir -p /knot-src/src && \
ln -sfn /usr/local/sbin/knotd /knot-src/src/knotd && \
ln -sfn /usr/local/sbin/knotc /knot-src/src/knotc && \
# Trim down the image
apt-get autoremove -q -y && \
apt-get clean && \
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
