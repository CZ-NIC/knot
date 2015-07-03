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
bugreport to the Knot DNS team. *Do NOT use the public mailing list 
for security issues (e.g. crash), though!* Instead, write to
`knot-dns@labs.nic.cz <mailto:knot-dns@labs.nic.cz>`_. All other bugs
and questions may be directed to the Knot DNS users mailing list
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

There are several ways to achieve that. The most common way is to
leave a core dump and then extract a backtrace from it. This doesn't
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

