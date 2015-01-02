FROM cznic/knot:latest
MAINTAINER Marek Vavrusa <marek.vavrusa@nic.cz>

# Install dependencies and sources 
RUN apt-get -q -y update; \
apt-get install -q -y \
python3 \
python3-pip \
bind9 \
bind9utils \
valgrind \
lsof \
gdb; \
pip3 install dnspython3; \
pip3 install psutil; \
apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/*

# Prepare the tests
RUN mkdir /tests; \
# Link the tested executables
mkdir /src; \
ln -sfn /usr/local/sbin/knotd /src/knotd; \
ln -sfn /usr/local/sbin/knotc /src/knotc

# Select entrypoint
WORKDIR /tests 
ENTRYPOINT ["/tests/runtests.py"]
