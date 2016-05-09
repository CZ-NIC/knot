.. highlight:: console

knotc – Knot DNS control utility
================================

Synopsis
--------

:program:`knotc` [*parameters*] *action* [*action_args*]

Description
-----------

If no *action* is specified, the program is executed in interactive mode.

Parameters
..........

**-c**, **--config** *file*
  Use a textual configuration file (default is :file:`@config_dir@/knot.conf`).

**-C**, **--confdb** *directory*
  Use a binary configuration database directory (default is :file:`@storage_dir@/confdb`).
  The default configuration database, if exists, has a preference to the default
  configuration file.

**-s**, **--socket** *path*
  Use a control UNIX socket path (default is :file:`@run_dir@/knot.sock`).

**-t**, **--timeout** *seconds*
  Use a control timeout in seconds. Set 0 for infinity (default is 5).

**-f**, **--force**
  Forced operation. Overrides some checks.

**-v**, **--verbose**
  Enable debug output.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

Actions
.......

**status**
  Check if the server is running.

**stop**
  Stop the server if running.

**reload**
  Reload the server configuration and modified zone files.

**zone-check** [*zone*...]
  Test if the server can load the zone. Semantic checks are executed if enabled
  in the configuration. (*)

**zone-memstats** [*zone*...]
  Estimate memory use for the zone. (*)

**zone-status** [*zone*...]
  Show the zone status. (*)

**zone-reload** [*zone*...]
  Trigger a zone reload from a disk without checking its modification time. For
  slave zone, the refresh from a master server is scheduled; for master zone,
  the notification of slave servers is scheduled.

**zone-refresh** [*zone*...]
  Trigger a check for the zone serial on the zone's master. If the master has a
  newer zone, a transfer is scheduled. This command is valid for slave zones.

**zone-retransfer** [*zone*...]
  Trigger a zone transfer from the zone's master. The server doesn't check the
  serial of the master's zone. This command is valid for slave zones.

**zone-flush** [*zone*...]
  Trigger a zone journal flush into the zone file.

**zone-sign** [*zone*...]
  Trigger a DNSSEC re-sign of the zone. Existing signatures will be dropped.
  This command is valid for zones with automatic DNSSEC signing.

**conf-init**
  Initialize the configuration database. (*)

**conf-check**
  Check the server configuration. (*)

**conf-import** *filename*
  Import a configuration file into the configuration database. Ensure the
  server is not using the configuration database! (*)

**conf-export** *filename*
  Export the configuration database into a config file. (*)

**conf-list** [*item*]
  List the configuration database sections or section items.

**conf-read** [*item*]
  Read the item from the active configuration database.

**conf-begin**
  Begin a writing configuration database transaction. Only one transaction
  can be opened at a time.

**conf-commit**
  Commit the configuration database transaction.

**conf-abort**
  Rollback the configuration database transaction.

**conf-diff** [*item*]
  Get the item difference in the transaction.

**conf-get** [*item*]
  Get the item data from the transaction.

**conf-set** *item* [*data*...]
  Set the item data in the transaction.

**conf-unset** [*item*] [*data*...]
  Unset the item data in the transaction.

Note
....

Empty *zone* parameter means all zones.

Type *item* parameter in the form of *section*\ [**[**\ *id*\ **]**\ ][**.**\ *name*].

(*) indicates a local operation which requires a configuration.

Interactive mode
................

The utility provides interactive mode with basic line editing functionality,
command completion, and command history.

Interactive mode behavior can be customized in `~/.editrc`. Refer to
:manpage:`editrc(5)` for details.

Command history is saved in `~/.knotc_history`.

Examples
--------

Reload the whole server configuration
.....................................

::

  $ knotc reload

Flush the example.com and example.org zones
...........................................

::

  $ knotc zone-flush example.com example.org

Get the current server configuration
....................................

::

  $ knotc conf-read server

Get the list of the current zones
.................................

::

  $ knotc conf-read zone.domain

Get the master remotes for the example.com zone
...............................................

::

  $ knotc conf-read 'zone[example.com].master'

Add example.org zone with a zonefile location
.............................................

::

  $ knotc conf-begin
  $ knotc conf-set 'zone[example.org]'
  $ knotc conf-set 'zone[example.org].file' '/var/zones/example.org.zone'
  $ knotc conf-commit

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`, :manpage:`editrc(5)`.
