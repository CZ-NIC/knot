.. highlight:: console

knotd – Knot DNS server daemon
==============================

Synopsis
--------

:program:`knotd` [*parameters*]

Description
-----------

Parameters
..........

**-c**, **--config** *file*
  Use a textual configuration file (default is :file:`@config_dir@/knot.conf`).

**-C**, **--confdb** *directory*
  Use a binary configuration database.

**-d**, **--daemonize** [*directory*]
  Run the server as a daemon. Working directory may be set (default is :file:`/`).

**-V**, **--version**
  Print the program versiom.

**-h**, **--help**
  Print help and usage.

See Also
--------

:manpage:`knotc(8)`, :manpage:`knot.conf(5)`.
