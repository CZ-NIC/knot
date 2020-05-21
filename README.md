# Requirements

`./doc/requirements.rst`

# Installation

`./doc/installation.rst`

## 1. Install prerequisites

### Debian based distributions
Update the system:
```bash
sudo apt-get update
sudo apt-get upgrade
```

#### Install prerequisites:
```bash
sudo apt-get install \
  libtool autoconf make pkg-config liburcu-dev libgnutls28-dev libedit-dev liblmdb-dev
```

#### Install optional packages:
```bash
sudo apt-get install \
  libcap-ng-dev libsystemd-dev libidn2-0-dev protobuf-c-compiler libfstrm-dev libmaxminddb-dev
```

### Fedora like distributions
#### Update the system:
```bash
dnf upgrade
```

#### Install basic development tools:
```bash
dnf install @buildsys-build
```

#### Install prerequisites:
```bash
dnf install \
  libtool autoconf pkgconfig automake userspace-rcu-devel gnutls-devel libedit-devel lmdb-devel
```

#### Install optional packages:
```bash
dnf install \
  libcap-ng-devel systemd-devel libidn2-devel protobuf-c-devel fstrm-devel libmaxminddb-devel
```

When compiling on RHEL based system, the Fedora EPEL repository has to be
enabled. Also for RHEL 6, forward compatibility package gnutls30-devel
with newer GnuTLS is required instead of gnutls-devel.

## 2. Install Knot DNS

Get the source code:
```bash
git clone https://gitlab.labs.nic.cz/knot/knot-dns.git
```
Or extract source package to knot-dns directory

Compile Knot:
```bash
cd knot-dns
autoreconf -if
./configure
make
```

Install Knot DNS into system:
```bash
sudo make install
sudo ldconfig
```

# Running

`./doc/operation.rst`

### 1. Each server needs configuration file.
Please see samples/knot.sample.conf,
project documentation, or man 5 knot.conf for more details.
Configuration file has to specify:
- storage for PID files, journal and timer databases etc.
- network interfaces
- served zones

E.g. use the default config file:
```bash
cd /etc/knot
mv knot.sample.conf knot.conf
```
Modify the config:
```bash
editor knot.conf
```

### 2. Prepare working directory
```bash
mv example.com.zone /var/lib/knot/
```

### 3. Start the server.
This can be done by running the 'knotd' command.
Alternatively, your distribution should have an init script available, if you've
installed Knot using a binary package.

Start Knot in the foreground to see if it runs:
```bash
knotd -c myserver.conf
```
