.. highlight:: console

knotc – Knot DNS control utility
================================

Synopsis
--------

:program:`knotc` [*parameters*] *action* [*action_args*]

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
  Reload the server configuration.


**zone-check** [*zone*...]
  Check the zone. (*)

**zone-memstats** [*zone*...]
  Estimate memory use for the zone. (*)

**zone-status** [*zone*...]
  Show the status of the zone. (*)

**zone-reload** [*zone*...]
  Trigger a zone reload.

**zone-refresh** [*zone*...]
  Trigger a zone refresh (if slave).

**zone-retransfer** [*zone*...]
  Trigger a zone retransfer (if slave).

**zone-flush** [*zone*...]
  Trigger a zone journal flush into the zone file.

**zone-sign** [*zone*...]
  Trigger a zone resign (if enabled).


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
----

Empty *zone* parameter means all zones.

Type *item* parameter in the form of *section*\ [**[**\ *id*\ **]**\ ][**.**\ *name*].

(*) indicates a local operation which requires a configuration available.

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

  $ knotc conf-read zone[example.com].master

Add example.org zone with a zonefile location
.............................................

::

  $ knotc conf-begin
  $ knotc conf-set zone[example.org]
  $ knotc conf-set zone[example.org].file "/var/zones/example.org.zone"
  $ knotc conf-commit

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
