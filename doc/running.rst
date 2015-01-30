.. meta::
   :description: reStructuredText plaintext markup language

.. _Running Knot DNS:

****************
Running Knot DNS
****************

The Knot DNS server part ``knotd`` can run either in the foreground or in the background,
with the ``-d`` option. When run in the foreground, it doesn't create a PID file.
Other than that, there are no differences and you can control it just the same way.

The tool ``knotc`` is designed as a front-end for user, making it easier to control running
server daemon. If you want to control the daemon directly, use ``SIGINT`` to quit
the process or ``SIGHUP`` to reload configuration.

If you do not pass any configuration via ``-c`` option, it will try to
search configuration in default path that is ``SYSCONFDIR/knot.conf``. The ``SYSCONFDIR``
depends on what you passed to the ``./configure``, usually ``/etc``.

Example of server start as a daemon::

    $ knotd -d -c knot.conf

Example of server stop::

    $ knotc -c knot.conf stop

For a complete list of actions refer to ``knotd -h`` and ``knotc -h``
or corresponding man pages.

Also, the server needs to create several files in order to run properly. These
files are stored in the folowing directories.

``storage`` (:ref:`storage`):

* *Zone files* - default directory for storing zone files. This can be
  overriden using absolute zone file location.

* *Journal files* - each zone has a journal file to store differences
  for IXFR and dynamic updates. Journal for zone ``example.com`` will
  be placed in ``example.com.diff.db``.

``rundir`` (:ref:`rundir`):

* *PID file* - is created automatically when the server is run in background.

* *Control sockets* - as a default, UNIX sockets are created here, but
  this can be overriden.

.. _Running a slave server:

Running a slave server
======================

Running the server as a slave is very straightforward as you usually
bootstrap zones over AXFR and thus avoid any manual zone compilation.
In contrast to AXFR, when the incremental transfer finishes, it stores
the differences in a journal file and doesn't update the zone file
immediately. There is a timer that checks periodically for new
differences and updates the zone file. You can configure this timer
with the ``zonefile-sync`` statement in ``zones`` (:ref:`zones`).

.. _Running a master server:

Running a master server
=======================

If you want to just check the zone files first before starting, you
can use ``knotc checkzone`` action::

    $ knotc -c master.conf checkzone example.com

For an approximate estimate of server's memory consumption, you can
use the ``knotc memstats`` action. This action prints count of
resource records, percentage of signed records and finally estimation
of memory consumption for each zone, unless otherwise
specified. Please note that estimated values might differ from the
actual consumption. Also, for slave servers with incoming transfers
enabled, be aware that the actual memory consumption might be double
or more during transfers::

    $ knotc -c master.conf memstats example.com

.. _Controlling running daemon:

Controlling running daemon
==========================

Knot DNS was designed to allow server reconfiguration on-the-fly
without interrupting its operation. Thus it is possible to change
both configuration and zone files and also add or remove zones without
restarting the server. This can be done with the ``knotc reload``
action::

    $ knotc -c master.conf reload

If you want *IXFR-out* differences created from changes you make to a
zone file, enable :ref:`ixfr-from-differences` in ``zones`` statement,
then reload your server as seen above. If *SOA*'s *serial* is not
changed no differences will be created.

If you want to refresh the slave zones, you can do this with the
``knotc refresh`` action::

    $ knotc -c slave.conf refresh

For the zone retransfer, there is also additional command ``-f``.
