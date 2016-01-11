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
the process or ``SIGHUP`` to reload the configuration.

If you pass neither configuration file (``-c`` parameter) nor configuration
database (``-C`` parameter), the server will first attempt to use the default
configuration database stored in ``/var/lib/knot/confdb`` or the
default configuration file stored in ``/etc/knot/knot.conf``. Both the
default paths can be reconfigured with ``--with-storage=path`` or
``--with-configdir=path`` respectively.

Example of server start as a daemon::

    $ knotd -d -c knot.conf

Example of server shutdown::

    $ knotc -c knot.conf stop

For a complete list of actions refer to the program help (``-h`` parameter)
or to the corresponding manual page.

Also, the server needs to create :ref:`server_rundir` and :ref:`zone_storage`
directories in order to run properly.

.. _Configuration database:

Configuration database
======================

In the case of a huge configuration file, the configuration can be stored
in a binary database. Such a database can be simply initialized::

    $ knotc conf-init

or preloaded from a file::

    $ knotc conf-import input.conf

Also the configuration database can be exported into a textual file::

    $ knotc conf-export output.conf

*Caution:* The import and export commands access the configuration database
directly, without any interaction with the server. So it is strictly
recommended to perform these operations when the server is not running.

.. _Dynamic configuration:

Dynamic configuration
=====================

The configuration database can be accessed using the server control interface
during the running server. To get the full power of the dynamic configuration,
the server must be started with a specified configuration database location
or with the default database initialized. Otherwise all the changes to the
configuration will be temporary (until the server stop).

*Note:* The database can be :ref:`imported<Configuration database>` in advance.

Most of the commands get an item name and value parameters. The item name is
in the form of ``section[identifier].name``. If the item is multivalued,
more values can be specified as individual (command line) arguments.

To get the list of configuration sections or to get the list of section items::

    $ knotc conf-list
    $ knotc conf-list server

To get the whole configuration or to get the whole configuration section or
to get all section identifiers or to get a specific configuration item::

    $ knotc conf-read
    $ knotc conf-read remote
    $ knotc conf-read zone.domain
    $ knotc conf-read zone[example.com].master

*Caution:* The following operations don't work on OpenBSD!

Modifying operations require an active configuration database transaction.
Just one transaction can be active at a time. Such a transaction then can
be aborted or commited. A semantic check is executed automatically before
every commit::

    $ knotc conf-begin
    $ knotc conf-abort
    $ knotc conf-commit

To set a configuration item value or to add more values or to add a new
section identifier or to add a value to all identified sections::

    $ knotc conf-set server.identity "Knot DNS"
    $ knotc conf-set server.listen 0.0.0.0@53 ::@53
    $ knotc conf-set zone[example.com]
    $ knotc conf-set zone.slave slave2

*Note:* Also the include operation can be performed. A non-absolute file
location is relative to the server binary path, not to the control binary path!::

    $ knotc conf-set include /tmp/new_zones.conf

To unset the whole configuration or to unset the whole configuration section
or to unset an identified section or to unset an item or to unset a specific
item value::

    $ knotc conf-unset
    $ knotc conf-unset zone
    $ knotc conf-unset zone[example.com]
    $ knotc conf-unset zone[example.com].master
    $ knotc conf-unset zone[example.com].master remote2 remote5

To get the change between the current configuration and the active transaction
for the whole configuration or for a specific section or for a specific
identified section or for a specific item::

    $ knotc conf-diff
    $ knotc conf-diff zone
    $ knotc conf-diff zone[example.com]
    $ knotc conf-diff zone[example.com].master

An example of possible configuration initialization::

    $ knotc conf-begin
    $ knotc conf-set server.listen 0.0.0.0@53 ::@53
    $ knotc conf-set remote[master_server]
    $ knotc conf-set remote[master_server].address 192.168.1.1
    $ knotc conf-set template[default]
    $ knotc conf-set template[default].storage /var/lib/knot/zones/
    $ knotc conf-set template[default].master master_server
    $ knotc conf-set zone[example.com]
    $ knotc conf-diff
    $ knotc conf-commit

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

If you just want to check the zone files before starting, you can use::

    $ knotc zone-check example.com

For an approximate estimation of server's memory consumption, you can use::

    $ knotc zone-memstats example.com

This action prints the count of resource records, percentage of signed
records and finally estimation of memory consumption for each zone, unless
specified otherwise. Please note that the estimated values may differ from the
actual consumption. Also, for slave servers with incoming transfers
enabled, be aware that the actual memory consumption might be double
or higher during transfers.

.. _Controlling running daemon:

Daemon controls
===============

Knot DNS was designed to allow server reconfiguration on-the-fly
without interrupting its operation. Thus it is possible to change
both configuration and zone files and also add or remove zones without
restarting the server. This can be done with::

    $ knotc reload

If you want to enable ixfr differences creation from changes you make to a
zone file, enable :ref:`zone_ixfr-from-differences` in the zone configuration
and reload your server as seen above. If *SOA*'s *serial* is not changed,
no differences will be created.

If you want to refresh the slave zones, you can do this with::

    $ knotc zone-refresh
