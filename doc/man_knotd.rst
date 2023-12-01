.. highlight:: none

``knotd`` – Knot DNS server daemon
==================================

Synopsis
--------

:program:`knotd` [*config_option*] [*options*]

Description
-----------

Knot DNS is a high-performance authoritative DNS server. The `knotd` program is
the DNS server daemon.

Config options
..............

**-c**, **--config** *file*
  Use a textual configuration file (default is :file:`@config_dir@/knot.conf`).

**-C**, **--confdb** *directory*
  Use a binary configuration database directory (default is :file:`@storage_dir@/confdb`).
  The default configuration database, if exists, has a preference to the default
  configuration file.

Options
.......

**-m**, **--max-conf-size** *MiB*
  Set maximum size of the configuration database
  (default is @conf_mapsize@ MiB, maximum 10000 MiB).

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
  Print the program version. The option **-VV** makes the program
  print the compile time configuration summary.

Signals
.......

If the `knotd` process receives a SIGHUP signal, it reloads its configuration and
reopens the log files, if they are configured. When `knotd` receives a SIGUSR1
signal, it reloads all configured zones. Upon receiving a SIGINT signal, `knotd`
exits.

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

See Also
--------

:manpage:`knot.conf(5)`, :manpage:`knotc(8)`, :manpage:`keymgr(8)`,
:manpage:`kjournalprint(8)`.
