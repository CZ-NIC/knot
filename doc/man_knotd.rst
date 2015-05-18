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

**-c**, **--config** *file*
  Use textual configuration file (default is :file:`@config_dir@/knot.conf`).

**-C**, **--confdb** *directory*
  Use binary configuration database.

**-d**, **--daemonize** [*directory*]
  Run server as a daemon. Working directory may be set (default is :file:`/`).

**-V**, **--version**
  Print program versiom.

**-h**, **--help**
  Print help and usage.

See Also
--------

:manpage:`knotc(8)`, :manpage:`knot.conf(5)`.
