****************
Running Knot DNS
****************

Knot DNS can run either in the foreground or in a background, with the @code{-d}
option. When run in foreground, it doesn't create a PID file. Other than that,
there are no differences and you can control it just the same way.

::

    Usage: knotd [parameters]
    
    Parameters:
     -c, --config <file>    Select configuration file.
     -d, --daemonize=[dir]  Run server as a daemon. Working directory may
                            be set.
     -v, --verbose          Verbose mode - additional runtime information.
     -V, --version          Print version of the server.
     -h, --help             Print help and usage.

Use knotc tool for convenience when working with the server daemon.
As of Knot DNS 1.3.0, the zones are not compiled anymore. That makes working
with the server much more user friendly.

::

    $ knotc -c knot.conf reload

TODO
