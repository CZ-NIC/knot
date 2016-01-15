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
  Use a binary configuration database directory (default is :file:`@storage_dir@/confdb`).
  The default configuration database, if exists, has a preference to the default
  configuration file.

**-s**, **--socket** *path*
  Use a remote control UNIX socket path (default is :file:`@run_dir@/knot.sock`).

**-d**, **--daemonize** [*directory*]
  Run the server as a daemon. New root directory may be specified
  (default is :file:`/`).

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

See Also
--------

:manpage:`knotc(8)`, :manpage:`knot.conf(5)`.
