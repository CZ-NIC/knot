.. highlight:: console

knotd -- Knot DNS server daemon
===============================

Synopsis
--------

:program:`knotd` [*parameters*]

Description
-----------

Parameters
..........

-c FILE, --config FILE
               Use textual configuration file (default is :file:`@config_dir@/knot.conf`).
-C DIRECTORY, --confdb DIRECTORY
               Use binary configuration database.
-d, --daemonize
	       Run server as a daemon, with default working directory (:file:`/`)
-d <DIRECTORY>, --daemonize <DIRECTORY>
               Run server as a daemon with specific working directory.
-V, --version  Print program versiom.
-h, --help     Print help and usage.

See Also
--------

:manpage:`knotc(8)`, :manpage:`knot.conf(5)`.
