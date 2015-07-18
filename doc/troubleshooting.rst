.. highlight:: console
.. _Troubleshooting:

***************
Troubleshooting
***************

First of all, check the logs. Enabling at least the ``warning`` message
severity may help you to identify some problems. See the :ref:`Logging section`
for details.

..  _Submitting a bugreport:

Reporting bugs
==============

If you are unable to solve the problem by yourself, you can submit a
bugreport to the Knot DNS developers. For security or sensitive issues
contact the developers directly on
`knot-dns@labs.nic.cz <mailto:knot-dns@labs.nic.cz>`_.
All other bugs and questions may be directed to the public Knot DNS users
mailing list
(`knot-dns-users@lists.nic.cz <mailto:knot-dns-users@lists.nic.cz>`_) or
may be entered into the
`issue tracking system <https://gitlab.labs.nic.cz/labs/knot/issues>`_.

Before anything else, please try to answer the following questions:

* Has it been working?
* What has changed? System configuration, software updates, network
  configuration, firewall rules modification, hardware replacement, etc.

The bugreport should contain the answers for the previous questions and in
addition at least the following information:

* Knot DNS version and type of installation (distribution package, from source,
  etc.)
* Operating system, processor architecture, kernel version
* Relevant basic hardware information (processor, amount of memory, available
  network devices, etc.)
* Description of the bug
* Log output with the highest verbosity (category ``any``, severity ``info``)
* Steps to reproduce the bug (if known)
* Backtrace (if the bug caused a crash or a hang; see the next section)

If possible, please provide a minimal configuration file and zone files which
can be used to reproduce the bug.

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
