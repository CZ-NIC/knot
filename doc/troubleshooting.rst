.. highlight:: console
.. _Troubleshooting:

***************
Troubleshooting
***************

First of all, check the logs (:ref:`Logging section`). Enabling at least
the ``warning`` message severity may help you identify some problems.

..  _Submitting a bugreport:

Submitting a bugreport
======================

If you are unable to solve the problem by yourself, you can submit a
bugreport to the Knot DNS team. For security issues (e.g. crash) do
not use the public mailing list.  Instead, write to
`knot-dns@labs.nic.cz <mailto:knot-dns@labs.nic.cz>`_. All other bugs
and questions may be directed to the Knot DNS users mailing list
(`knot-dns-users@lists.nic.cz <mailto:knot-dns-users@lists.nic.cz>`_).

The bugreport should contain at least:

* Knot DNS version and type of installation (source, package, etc.)
* Type and version of your operating system
* Basic hardware information
* Description of the bug
* Log output of all messages (category ``any``, severity ``info``)
* Steps to reproduce the bug (if known)
* Backtrace (if the bug caused a crash; see next section)

If it is possible, the actual configuration file and/or zone file(s)
will be very useful as well.

..  _Generating backtrace:

Generating backtrace
====================

There are several ways to achieve that, the most common way is to
leave core dumps and then extract a backtrace from it. This doesn't
affect any server operation, you just need to make sure the OS is
configured to generate them::

    $ ulimit -c unlimited                  # Enable unlimited core dump size
    ...
    $ gdb $(which knotd) core.<KNOT_PID>   # Start gdb on the core dump
    (gdb) thread apply all bt              # Extract backtrace from all threads
    (gdb) q

If the error is repeatable, you can run the binary in a ``gdb``
debugger or attach the debugger to the running process. The backtrace
from a running process is generally useful when debugging problems
like stuck process and similar::

    $ knotd -c knot.conf
    $ sudo gdb --pid <KNOT_PID>
    (gdb) continue
    ...
    (gdb) thread apply all bt
    (gdb) q

..  _Debug messages:

Debug messages
==============

In some cases the aforementioned information may not be enough to find
and fix the bug. In these cases it may be useful to turn on debug
messages.

Two steps are required in order to log debug messages. First you need
to allow the debug messages in the server. Then the logging must be
configured to log debug messages (:ref:`Logging section`). It is recommended to
log these messages to a file. Firstly, the debug output may be rather
large and secondly, it is easier to use the data for debugging.

..  _Enabling debug messages:

Enabling debug messages
-----------------------

Allowing debug messages in the server is possible only when
configuring the sources. Two ``configure`` options are required
to do this:

* The ``--enable-debug`` option specifies the server modules for which
  you want to enable debug messages. One or more of the following
  modules may be listed, separated by commas:

  * ``server`` - Messages related to networking, threads and low-level
    journal handling.
  * ``zones`` - All operations with zones (loading, updating, saving,
    timers, high-level journal management).
  * ``ns`` - Query processing, high-level handling of all requests
    (transfers, notifies, normal queries).
  * ``loader`` - Zone loading and semantic checks.
  * ``dnssec`` - DNSSEC operations.

* The ``--enable-debuglevel`` option is used to specify the verbosity
  of the debug output. Be careful with this, as the ``details``
  verbosity may produce really large logs (in order of GBs).  There are
  three levels of verbosity: ``brief``, ``verbose`` and ``details``.

Example:

::

    $ ./configure --enable-debug=server,zones --enable-debuglevel=verbose
