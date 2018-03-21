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

**-m**, **--max-conf-size** *MiB*
  Set maximum configuration size (default is @conf_mapsize@ MiB, maximum 10000 MiB).

**-s**, **--socket** *path*
  Use a remote control UNIX socket path (default is :file:`@run_dir@/knot.sock`).

**-d**, **--daemonize** [*directory*]
  Run the server as a daemon. New root directory may be specified
  (default is :file:`/`).

**-v**, **--verbose**
  Enable debug output.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

See Also
--------

:manpage:`knot.conf(5)`, :manpage:`knotc(8)`, :manpage:`keymgr(8)`,
:manpage:`kjournalprint(1)`.
