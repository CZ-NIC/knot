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

**zone-sing** [*zone*...]
  Trigger a zone resign (if enabled).


**conf-init**
  Initialize the confdb. (*)

**conf-check**
  Check the server configuration. (*)

**conf-import** *filename*
  Import a config file into the confdb. Ensure the server is not accessing
  the confdb! (*)

**conf-export** *filename*
  Export the confdb into a config file. (*)

**conf-list** [*item*]
  List the confdb sections or section items.

**conf-read** [*item*]
  Read the item from the active confdb.

**conf-begin**
  Begin a writing confdb transaction. Only one transaction can be opened at a time.

**conf-commit**
  Commit the confdb transaction.

**conf-abort**
  Rollback the confdb transaction.

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

(*) indicates a local operation requiring a configuration specified.

Examples
--------

Reload the whole server configuration
.....................................

::

  $ knotc reload

Flush the example.com and example.eu zones
..........................................

::

  $ knotc zone-flush example.com example.eu

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

Add example.eu zone with a zonefile location
............................................

::

  $ knotc conf-begin
  $ knotc conf-set zone[example.eu]
  $ knotc conf-set zone[example.eu].file "/var/zones/example.eu.zone"
  $ knotc conf-commit

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
