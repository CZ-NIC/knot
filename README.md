[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/CZ-NIC/knot.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/CZ-NIC/knot/context:cpp)
[![Coverity Status](https://img.shields.io/coverity/scan/knot-dns.svg)](https://scan.coverity.com/projects/knot-dns)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/knot-dns.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:knot-dns)
[![Documentation Status](https://readthedocs.org/projects/knot/badge/?version=master)](https://knot.readthedocs.io/en/master/)

# Requirements

[doc/requirements.rst](doc/requirements.rst)

# Installation

[doc/installation.rst](doc/installation.rst)

## 1. Install prerequisites

### Debian based distributions

#### Update the system:
```bash
sudo apt-get update
sudo apt-get upgrade
```

#### Install prerequisites:
```bash
sudo apt-get install \
  libtool autoconf automake make pkg-config liburcu-dev libgnutls28-dev libedit-dev liblmdb-dev
```

#### Install optional packages:
```bash
sudo apt-get install \
  libcap-ng-dev libsystemd-dev libidn2-0-dev libprotobuf-c-dev protobuf-c-compiler libfstrm-dev libmaxminddb-dev libnghttp2-dev libmnl-dev
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
  libtool autoconf automake pkgconfig userspace-rcu-devel gnutls-devel libedit-devel lmdb-devel
```

#### Install optional packages:
```bash
dnf install \
  libcap-ng-devel systemd-devel libidn2-devel protobuf-c-devel fstrm-devel libmaxminddb-devel libnghttp2-devel libmnl-devel
```

When compiling on RHEL based system, the Fedora EPEL repository has to be
enabled. Also for RHEL 6, forward compatibility package gnutls30-devel
with newer GnuTLS is required instead of gnutls-devel.

## 2. Install Knot DNS

Get the source code:
```bash
git clone https://gitlab.nic.cz/knot/knot-dns.git
```
Or extract source package to knot-dns directory.

Compile the source code:
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

### 1. Ensure some configuration

[doc/configuration.rst](doc/configuration.rst)

Please see [samples/knot.sample.conf](samples/knot.sample.conf),
[project documentation](https://www.knot-dns.cz/documentation/),
or `man 5 knot.conf` for more details. Basically the configuration should specify:
- network interfaces
- served zones

E.g. use the default configuration file:
```bash
cd /etc/knot
mv knot.sample.conf knot.conf
```
Modify the configuration file:
```bash
editor knot.conf
```

### 2. Prepare working directory

```bash
mv example.com.zone /var/lib/knot/
```

### 3. Start the server

[doc/operation.rst](doc/operation.rst)

This can be done by running the `knotd` command. Alternatively, your distribution
should have an init script available, if you installed Knot DNS from a binary package.

Start the server in foreground to see if it runs:
```bash
knotd -c /etc/knot/knot.conf
```
