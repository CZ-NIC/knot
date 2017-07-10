.. highlight:: console
.. _Installation:

************
Installation
************

.. _Installation from a package_:

Installation from a package
===========================

Knot DNS may already be included in your operating system distribution and
therefore can be installed from packages (Linux), ports (BSD), or via
Homebrew (macOS). This is always preferred unless you want to test the latest
features, contribute to Knot development, or you just know what you are doing.

See the project `download <https://www.knot-dns.cz/download>`_ page for
the latest information.

.. _Installation from the source code:

Installation from the source code
=================================

Required build environment
--------------------------

The build process relies on these standard tools:

* make
* libtool
* pkg-config
* autoconf >= 2.65
* python-sphinx (optional, for documentation building)

GCC at least 4.1 is strictly required for atomic built-ins, but the latest
available version is recommended. Another requirements ``_GNU_SOURCE``
and C99 support, otherwise it adapts to the compiler available features.
LLVM clang compiler since version 2.9 can be used as well.

Getting the source code
-----------------------

You can find the source code for the latest release on `www.knot-dns.cz <https://www.knot-dns.cz>`_.
Alternatively, you can fetch the whole project from the git repository
`git://git.nic.cz/knot-dns.git <https://gitlab.labs.nic.cz/knot/knot-dns/tree/master>`_.

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

.. NOTE::
   The compilation with enabled optimizations may take a long time. In such
   a case the ``--disable-fastparser`` configure option can help.

Installation
------------

When you have finished building Knot DNS, it's time to install the
binaries and configuration files into the operation system hierarchy.
You can do so by executing::

    $ make install

When installing as a non-root user, you might have to gain elevated privileges by
switching to root user, e.g. ``sudo make install`` or ``su -c 'make install'``.
