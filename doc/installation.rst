.. highlight:: console
.. _Installation:

************
Installation
************

.. _Required build environment:

Required build environment
==========================

GCC at least 4.1 is strictly required for atomic built-ins, but the latest
available version is recommended. Another requirement is ``_GNU_SOURCE``
support, otherwise it adapts to the compiler available features.

LLVM clang compiler can be used as well. However, the compilation with
enabled optimizations will take a long time, unless the ``--disable-fastparser``
configure option is given.

Knot DNS build system relies on these standard tools:

* make
* libtool
* autoconf >= 2.65

.. _Required libraries:

Required libraries
==================

Knot DNS requires few libraries to be compiled:

* GnuTLS, at least 3.3
* Jansson, at least 2.3
* Userspace RCU, at least 0.5.4
* libedit
* lmdb (included)
* libcap-ng, at least 0.6.4 (optional)
* libidn (optional)
* libsystemd (optional)
* protobuf-c and fstrm (optional)

The LMDB library is required. It is included with the Knot DNS source code,
however linking with the system library is preferred.

If the libcap-ng library is available, Knot DNS will take advantage of the
POSIX 1003.1e :manpage:`capabilites(7)` by sandboxing the exposed threads.
Most rights are stripped from the exposed threads for security reasons.

The libidn library is a prerequisite for IDNA2003 (International Domain Names)
support in Knot DNS utilities.

If the libsystemd library is available, the server will use systemd's startup
notifications mechanism and journald for logging.

If the protobuf-c and fstrm libraries are available, the support for logging
in Dnstap format will be included.

.. _Installation from source code:

Installation from source code
=============================

You can find the source code for the latest release on `www.knot-dns.cz <https://www.knot-dns.cz>`_.
Alternatively, you can fetch the whole project from the git repository
`git://git.nic.cz/knot-dns.git <https://gitlab.labs.nic.cz/labs/knot/tree/master>`_.

After obtaining the source code, the compilation and installation is a
quite straightforward process using autotools.

.. _Configuring and generating Makefiles:

Configuring and generating Makefiles
------------------------------------

If compiling from the git source, you need to bootstrap the ``./configure`` file first::

    $ autoreconf -i -f

In most cases, you can just run configure without any options::

    $ ./configure

For all available configure options run::

    $ ./configure --help

Compilation
-----------

After running ``./configure`` you can compile Knot DNS by running
``make`` command, which will produce binaries and other related
files::

    $ make

Installation
------------

When you have finished building Knot DNS, it's time to install the
binaries and configuration files into the operation system hierarchy.
You can do so by executing::

    $ make install

When installing as a non-root user, you might have to gain elevated privileges by
switching to root user, e.g. ``sudo make install`` or ``su -c 'make install'``.

.. _OS specific installation:

OS specific installation
========================

Knot DNS might already be available in the destination operating system
repository.

Debian Linux
------------

Knot DNS is already available from Debian 7 (Wheezy) upwards. In addition
to the official packages we also provide custom repository, which can
be used by adding::

    deb     http://deb.knot-dns.cz/debian/ <codename> main
    deb-src http://deb.knot-dns.cz/debian/ <codename> main

to your ``/etc/apt/sources.list`` or into separate file in
``/etc/apt/sources.list.d/``.

As an example, for Debian 8 (Jessie) the Knot DNS packages can be added by
executing following command as the root user::

    # cat >/etc/apt/sources.list.d/knot.list <<EOF
    deb     http://deb.knot-dns.cz/debian/ jessie main
    deb-src http://deb.knot-dns.cz/debian/ jessie main
    EOF
    # apt-get update
    # apt-get install knot

Ubuntu Linux
------------

Prepackaged version of Knot DNS can be found in Ubuntu from
version 12.10 (Quantal Quetzal). In addition to the package included
in the main archive, we provide Personal Package Archive (PPA) as an
option in order to upgrade to the last stable version of Knot DNS or to install
it on older versions of Ubuntu Linux.

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

Fedora Linux
------------

The RPM packages for Knot DNS are available in official Fedora
repositories since Fedora 18 (Spherical Cow). Search for the ``knot``
package in your package manager. To install the package using Yum, run
the following command as the root user::

    # yum install knot

Arch Linux
----------

Knot DNS is available in the official package repository (AUR). To install the
package, run::

    # pacman -S knot

Gentoo Linux
------------

Knot DNS is also available in the Gentoo package repository. However, you will
probably need to unmask the package prior to starting the installation::

    # emerge -a knot

FreeBSD
-------

Knot DNS is in ports tree under ``dns/knot``. To install the port, run::

    # cd /usr/ports/dns/knot
    # make install
