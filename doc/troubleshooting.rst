.. highlight:: console
.. _Troubleshooting:

***************
Troubleshooting
***************

First of all, check the logs (:ref:`Logging section`). Enabling at least
the ``warning`` message severity may help you to identify some problems.

..  _Submitting a bugreport:

Reporting bugs
==============

If you are unable to solve the problem by yourself, you can submit a
bugreport to the Knot DNS developers. For security or sensitive issues
contact the developers directly on
`knot-dns@labs.nic.cz <mailto:knot-dns@labs.nic.cz>`_.
All other bugs and questions may be directed to the Knot DNS users public
mailing list
(`knot-dns-users@lists.nic.cz <mailto:knot-dns-users@lists.nic.cz>`_).

A bugreport should contain at least:

* Knot DNS version and type of installation (source, package, etc.)
* Type and version of your operating system
* Basic hardware information
* Description of the bug
* Log output of all messages (category ``any``, severity ``info``)
* Steps to reproduce the bug (if known)
* Backtrace (if the bug caused a crash; see the next section)

If it is possible, the actual configuration file and/or zone file(s)
will be very useful as well.

..  _Generating backtrace:

Generating backtrace
====================

There are several ways to get a backtrace. The most common way is to extract
the backtrace from a core dump file. Core dump is a memory snapshot generated
by the operating system when a process crashes. The generating of core dumps must
be usually enabled::

    $ ulimit -c unlimited                  # Enable unlimited core dump size
    $ knotd ...                            # Reproduce the crash
    ...
    $ gdb knotd <core-dump-file>           # Start gdb on the core dump
    (gdb) thread apply all bt              # Extract backtrace from all threads
    (gdb) quit

To save the backtrace into a file, the following GDB commands can be used::

    (gdb) set pagination off
    (gdb) set logging file backtrace.txt
    (gdb) set logging on
    (gdb) thread apply all bt
    (gdb) set logging off

To generate a core dump of a running process, the `gcore` utility can be used::

    $ gcore -o <output-file> $(pidof knotd)

Please note that core dumps can be intercepted by an error-collecting system
service (systemd-coredump, ABRT, Apport, etc.). If you are using such a service,
consult its documentation about core dump retrieval.

If the error is reproducible, it is also possible to start and inspect the
server directly in the debugger::

    $ gdb --args knotd -c /etc/knot.conf
    (gdb) run
    ...

Alternatively, the debugger can be attached to a running server
process. This is generally useful when troubleshooting a stuck process::

    $ knotd ...
    $ gdb --pid $(pidof knotd)
    (gdb) continue
    ...
