.. _Knot DNS Installation:

*********************
Knot DNS Installation
*********************

.. _Required build environment:

Required build environment
==========================

GCC at least 4.1 is strictly required for atomic built-ins, but 4.2 or
newer is recommended.  Another requirement is ``_GNU_SOURCE`` support,
otherwise it adapts to the compiler available features.  LLVM clang
works, but it is not officially supported.

Knot DNS build system relies on these standard tools:

* make
* libtool
* autoconf >= 2.65
* flex >= 2.5.31
* bison >= 2.3

.. _Required libraries:

Required libraries
==================

Knot DNS requires few libraries to be compiled:

* OpenSSL, at least 0.9.8
* zlib
* Userspace RCU, at least 0.5.4
* libcap-ng, at least 0.6.4 (optional library)

If libcap-ng library is available, Knot DNS will take advantage of the
POSIX 1003.1e capabilites(7) by sandboxing the exposed threads.  Most
rights are stripped from the exposed threads for security reasons.

You can probably find OpenSSL and zlib libraries already included in
your system or distribution.  If not, zlib resides at http://zlib.net,
and OpenSSL can be found at http://www.openssl.org.

.. _Userspace RCU:

Userspace RCU
-------------

liburcu is a LGPLv2.1 userspace RCU (read-copy-update) library. This
data synchronization library provides read-side access which scales
linearly with the number of cores. It does so by allowing multiple
copies of a given data structure to live at the same time, and by
monitoring the data structure accesses to detect grace periods after
which memory reclamation is possible.  `Userspace RSU <http://lttng.org/urcu>`

Binary packages for Debian can be found under ``liburcu1`` for the
library and ``liburcu-dev`` for development files.

Minimum supported version of Userspace RCU library is 0.5.4,
but we recommend using latest available version.
It is crucial especially on non-Linux systems, as we got some compatibility
patches accepted to later releases of Userspace RCU.
OpenBSD, NetBSD and OS X platforms are supported from version 0.7.0.

.. _Installation from the source:

Installation from the sources
=============================

You can find the source files for the latest release on `www.knot-dns.cz <https://www.knot-dns.cz>`.
Alternatively, you can fetch the sources from git repository `<git://git.nic.cz/knot-dns.git>`.

After unpacking the sources, the compilation and installation is a
quite straightforward process using autotools.

.. _Configuring and generating Makefiles:

Configuring and generating Makefiles
------------------------------------

If you want to compile from Git sources, you need to bootstrap the ``./configure`` file first.::

    $ autoreconf -i -f

For all available configure options run::

    $ ./configure --help

If you have trouble with unknown syscalls under valgrind, disable recvmmsg by
adding a parameter ``--enable-recvmmsg=no`` to configure.

Knot DNS has also support for link time optimizations.  You can enable
it by the configure parameter ``./configure --enable-lto=yes``.  It is
however disabled by default as it is known to be broken in some
compiler versions and may result in an unexpected behaviour.  Link
time optimizations also disables the possibility to debug the
resulting binaries.

If you want to add debug messages, there are two steps to do that.
First you have to enable modules you are interested in.
Available are: ``server, zones, xfr, packet, dname, rr, ns, hash, compiler``.
You can combine multiple modules as a comma-separated list.
Then you can narrow the verbosity of the debugging message by specifying the
verbosity as ``brief, verbose, details``.

For example::

    $ ./configure --enable-debug=server,packet --enable-debuglevel=brief
    $ ./configure --enable-debug=server,packet --enable-debuglevel=verbose

For more detailed information, see @ref{Debug messages}. ##TODO

In most simple case you can just run configure without any options::

    $ ./configure

Compilation
-----------

(After running ``./configure`` you can compile Knot DNS by running
``make`` command, which will produce binaries and other related
files::

    $ make

Knot DNS build process is safe to parallelize using ``make -j N``,
where N is number of concurrent processes.  Using this option can
increase speed of the compilation.

For example to use maximum 8 concurrent processes you would use::

    $ make -j 8

Installation
------------

When you have finished building the Knot DNS, it's time to install the
binaries and configuration files into the operation system hierarchy.
You can do so by executing ``make install`` command.  When installing
as a non-root user you might have to gain elevated privileges by
switching to root user, e.g. ``sudo make install`` or ``su -c 'make install'``::

    $ make install

Installation from packages
==========================

In addition to providing the packages in .DEB and .RPM format, the
Knot DNS might already be available in your favourite distribution, or
in a ports tree.

Installing Knot DNS packages on Debian
--------------------------------------

Knot DNS is already available from Debian wheezy upwards.  In addition
to the official packages we also provide custom repository, which can
be used by adding::

    deb     http://deb.knot-dns.cz/debian/ <codename> main
    deb-src http://deb.knot-dns.cz/debian/ <codename> main

to your ``/etc/apt/sources.list`` or into separate file in
``/etc/apt/sources.list.d/``.

As an example, for Debian squeeze (current stable) the Knot DNS
packages can be added by executing following command as the root user::

    $ cat >/etc/apt/sources.list.d/knot.list <<EOF
    deb     http://deb.knot-dns.cz/debian/ <codename> main
    deb-src http://deb.knot-dns.cz/debian/ <codename> main
    EOF
    $ apt-get update
    $ apt-get install knot

Installing Knot DNS packages on Ubuntu
--------------------------------------

Prepackaged version of the Knot DNS can be found in Ubuntu from
version 12.10 (Quantal Quetzal).  In addition to the package included
in the main archive, we provide Personal Package Archive (PPA) as an
option to upgrade to last stable version of the Knot DNS or to install
it on older versions of Ubuntu Linux.

We typically provide packages for all supported versions of Ubuntu
Linux including 5 year support for `LTS <https://wiki.ubuntu.com/LTS>`
versions of Ubuntu Linux.  At the time of writing this manual this
includes Ubuntu 10.04 LTS, 11.04, 11.10 and 12.04 LTS.

Adding official PPA repository for Knot DNS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To start installing and using software from a Personal Package
Archive, you first need to tell Ubuntu where to find the PPA::

    $ sudo add-apt-repository ppa:cz.nic-labs/knot-dns
    $ sudo apt-get update
    $ sudo apt-get install knot

Running this sequence of commands will ensure that you will
install Knot DNS on your system and keep it up-to-date
in the future, when new versions are released.

Installing Knot DNS packages on Fedora
--------------------------------------

The RPM packages for ``Knot DNS`` are available in official Fedora
repositories since Fedora 18 (Spherical Cow). Look for ``knot``
package in your package manager. To install the package using Yum, run
a following command as the root user::

    # yum install knot

Using official distribution repository is highly recommended, however you may
want to run ``Knot DNS`` on older releases of Fedora. In this case you can
set up an unofficial repository by creating @file{/etc/yum.repos.d/knot.conf}
file with the following content::

    [knot]
    name=Network.CZ Repository
    baseurl=ftp://repo.network.cz/pub/redhat/
    enabled=1
    gpgcheck=0
    gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-network.cz

After performing this action, you can install ``knot`` package the same way
as described above. Please note that the unofficial repository contains only
builds for i686 and x86_64 architecture.

When upgrading to Fedora 18 or higher, backup the configuration and
switch to the latest package provided in the official repository by running the
following command as the root user:

    # yum distro-sync knot


Installing Knot DNS from ports on FreeBSD
-----------------------------------------

Knot DNS is in ports tree under ``dns/knot``::

    $ cd /usr/ports/dns/knot
    $ sudo make install

Installing Knot DNS on Arch Linux
---------------------------------

Knot DNS is available official package repository (AUR)::

    https://aur.archlinux.org/packages/knot/

Installing Knot DNS on Gentoo Linux
-----------------------------------

Knot DNS is available from Gentoo package repository::

    https://packages.gentoo.org/package/net-dns/knot
