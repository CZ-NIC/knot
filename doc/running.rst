.. _Running Knot DNS:

****************
Running Knot DNS
****************

Knot DNS can run either in the foreground or in a background, with the ``-d``
option. When run in foreground, it doesn't create a PID file. Other than that,
there are no differences and you can control it just the same way.

::

    Usage: knotd [parameters]

    Parameters:
     -c, --config <file>    Select configuration file.
     -d, --daemonize=[dir]  Run server as a daemon. Working directory may
                            be set.
     -V, --version          Print version of the server.
     -h, --help             Print help and usage.

Use knotc tool for convenience when working with the server daemon.
As of Knot DNS 1.3.0, the zones are not compiled anymore. That makes working
with the server much more user friendly.

::

    $ knotc -c knot.conf reload

The tool ``knotc`` is designed as a front-end for user, making it easier to control running server daemon.
If you want to control the daemon directly, use ``SIGINT`` to quit the process or ``SIGHUP`` to reload configuration.

::

    Usage: knotc [parameters] <action> [action_args]

    Parameters:
     -c, --config <file>    Select configuration file.
     -s <server>            Remote UNIX socket/IP address (default
                            ${rundir}/knot.sock).
     -p <port>              Remote server port (only for IP).
     -y <[hmac:]name:key>   Use key specified on the command line
                            (default algorithm is hmac-md5).
     -k <file>              Use key file (as in config section 'keys').
     -f, --force            Force operation - override some checks.
     -v, --verbose          Verbose mode - additional runtime information.
     -V, --version          Print knot server version.
     -i, --interactive      Interactive mode (do not daemonize).
     -h, --help             Print help and usage.

    Actions:
     stop                   Stop server.
     reload                 Reload configuration and changed zones.
     refresh <zone>         Refresh slave zone (all if not specified).
     flush                  Flush journal and update zone files.
     status                 Check if server is running.
     zonestatus             Show status of configured zones.
     checkconf              Check current server configuration.
     checkzone <zone>       Check zone (all if not specified).
     memstats <zone>        Estimate memory consumption for zone (all if not
                            specified).

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
immediately.  There is a timer that checks periodically for new
differences and updates the zone file. You can configure this timer
with the ``zonefile-sync`` statement in ``zones`` (:ref:`zones`).

There are two ways to start the server - in foreground or background.
First, let's start in foreground. If you do not pass any configuration, it will try to
search configuration in default path that is ``SYSCONFDIR/knot.conf``. The ``SYSCONFDIR``
depends on what you passed to the ``./configure``, usually ``/etc``.

::

    $ knotd -c slave.conf

To start it as a daemon, just add a ``-d`` parameter. Unlike the foreground mode,
PID file will be created in ``rundir`` directory.

    $ knotd -d -c slave.conf # start the daemon
    $ knotc -c slave.conf stop # stop the daemon

When the server is running, you can control the daemon, see :ref:`Controlling running daemon`.

.. _Running a master server:

Running a master server
=======================

If you want to just check the zone files first before starting, you
can use ``knotc checkzone`` action::

    $ knotc -c master.conf checkzone example.com

For an approximate estimate of server's memory consumption, you can
use the ``knotc memstats`` action.  This action prints count of
resource records, percentage of signed records and finally estimation
of memory consumption for each zone, unless specified
otherwise. Please note that estimated values might differ from the
actual consumption. Also, for slave servers with incoming transfers
enabled, be aware that the actual memory consumption might be double
or more during transfers.

::

    $ knotc -c master.conf memstats example.com

Starting and stopping the daemon is the same as with the slave server in the previous section.

.. _Controlling running daemon:

Controlling running daemon
==========================

Knot DNS was designed to allow server reconfiguration on-the-fly
without interrupting its operation.  Thus it is possible to change
both configuration and zone files and also add or remove zones without
restarting the server.  This can be done with the ``knotc reload``
action.

::

    $ knotc -c master.conf reload  # reconfigure and load updated zones

If you want *IXFR-out* differences created from changes you make to a
zone file, enable :ref:`ixfr-from-differences` in ``zones`` statement,
then reload your server as seen above.  If *SOA*'s *serial* is not
changed no differences will be created.

If you want to force refresh the slave zones, you can do this with the
``knotc refresh`` action::

    $ knotc -c slave.conf refresh

For a complete list of actions refer to ``knotc --help`` command
output.
