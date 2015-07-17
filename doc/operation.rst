.. highlight:: console
.. _Operation:

*********
Operation
*********

The Knot DNS server part ``knotd`` can run either in the foreground, or in the background
using the ``-d`` option. When run in the foreground, it doesn't create a PID file.
Other than that, there are no differences and you can control both the same way.

The tool ``knotc`` is designed as a user front-end, making it easier to control running
server daemon. If you want to control the daemon directly, use ``SIGINT`` to quit
the process or ``SIGHUP`` to reload configuration.

If you pass neither configuration file (``-c`` parameter) nor configuration
database (``-C`` parameter), server will attempt to use the default configuration
file stored in ``SYSCONFDIR/knot/knot.conf`` (the path can be reconfigured with
``--with-configdir=path``).

Example of server start as a daemon::

    $ knotd -d -c knot.conf

Example of server shutdown::

    $ knotc -c knot.conf stop

For a complete list of actions refer to ``knotd -h`` and ``knotc -h``
or corresponding man pages.

Also, the server needs to create :ref:`server_rundir` and :ref:`zone_storage`
directories in order to run properly.

.. _Configuration database:

Configuration database
======================

In the case of a huge configuration file, the configuration can be preloaded
into the server's configuration database::

    $ knotc import input.conf

Also the configuration database can be exported into a configuration file::

    $ knotc export output.conf

It is recommended to perform these actions without server running.

.. _Running a slave server:

Slave mode
==========

Running the server as a slave is very straightforward as you usually
bootstrap zones over AXFR and thus avoid any manual zone operations.
In contrast to AXFR, when the incremental transfer finishes, it stores
the differences in the journal file and doesn't update the zone file
immediately but after the :ref:`zone_zonefile-sync` period elapses.

.. _Running a master server:

Master mode
===========

If you just want to check the zone files before starting, you
can use the ``knotc checkzone`` action::

    $ knotc -c master.conf checkzone example.com

For an approximate estimation of server's memory consumption, you can
use the ``knotc memstats`` action. This action prints the count of
resource records, percentage of signed records and finally estimation
of memory consumption for each zone, unless specified otherwise.
Please note that the estimated values may differ from the
actual consumption. Also, for slave servers with incoming transfers
enabled, be aware that the actual memory consumption might be double
or higher during transfers::

    $ knotc -c master.conf memstats example.com

.. _Controlling running daemon:

Daemon controls
===============

Knot DNS was designed to allow server reconfiguration on-the-fly
without interrupting its operation. Thus it is possible to change
both configuration and zone files and also add or remove zones without
restarting the server. This can be done with the ``knotc reload``
action::

    $ knotc -c master.conf reload

If you want to enable ixfr differences creation from changes you make to a
zone file, enable :ref:`zone_ixfr-from-differences` in the zone configuration
and reload your server as seen above. If *SOA*'s *serial* is not changed,
no differences will be created.

If you want to refresh the slave zones, you can do this with the
``knotc refresh`` action::

    $ knotc -c slave.conf refresh

For the zone retransfer, there is also an additional command ``-f``.
