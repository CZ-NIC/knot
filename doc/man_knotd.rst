.. highlight:: console

knotd – Knot DNS server daemon
==============================

.. _knotd_synopsis:

Synopsis
--------

:program:`knotd` [*parameters*]

.. _knotd_description:

Description
-----------

.. _knotd_parameters:

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

**-v**, **--verbose**
  Enable debug output.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

.. _knotd_see_also:

See Also
--------

:manpage:`knot.conf(5)`, :manpage:`knotc(8)`, :manpage:`keymgr(8)`,
:manpage:`kjournalprint(1)`.
