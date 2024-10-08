.. highlight:: none
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
features, contribute to Knot development, or you know what you are doing.

See the project `download <https://www.knot-dns.cz/download>`_ page for
the latest information.

.. _Installation from source code:

Installation from source code
=============================

Required build environment
--------------------------

The build process relies on these standard tools:

* make
* libtool
* pkg-config
* autoconf >= 2.65
* python-sphinx (optional, for documentation building)

A GCC or LLVM Clang compiler with C11 support.

Getting the source code
-----------------------

You can find the source code for the latest release on `www.knot-dns.cz <https://www.knot-dns.cz>`_.
Alternatively, you can fetch the whole project from the git repository
`https://gitlab.nic.cz/knot/knot-dns.git <https://gitlab.nic.cz/knot/knot-dns>`_.

After obtaining the source code, compilation and installation is quite a
straightforward process using autotools.

.. _Configuring and generating Makefiles:

Configuring and generating Makefiles
------------------------------------

If compiling from git source, you need to bootstrap the ``./configure`` file first::

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
