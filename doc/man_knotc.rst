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

**-m**, **--max-conf-size** *MiB*
  Set maximum size of the configuration database
  (default is @conf_mapsize@ MiB, maximum 10000 MiB).

**-s**, **--socket** *path*
  Use a control UNIX socket path (default is :file:`@run_dir@/knot.sock`).

**-t**, **--timeout** *seconds*
  Use a control timeout in seconds. Set to 0 for infinity (default is 60).
  The control socket operations are also subject to the :ref:`timeout<control_timeout>`
  parameter set on the server side in server's Control configuration section.

**-b**, **--blocking**
  Zone event trigger commands wait until the event is finished.

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

**status** [*detail*]
  Check if the server is running. Details are **version** for the running
  server version, **workers** for the numbers of worker threads,
  or **configure** for the configure summary.

**stop**
  Stop the server if running.

**reload**
  Reload the server configuration and modified zone files. All open zone
  transactions will be aborted!

**stats** [*module*\ [\ **.**\ *counter*\ ]]
  Show global statistics counter(s). To print also counters with value 0, use
  force option.

**zone-status** *zone* [*filter*]
  Show the zone status. Filters are **+role**, **+serial**, **+transaction**,
  **+events**, and **+freeze**.

**zone-check** [*zone*...]
  Test if the server can load the zone. Semantic checks are executed if enabled
  in the configuration. If invoked with the force option, an error is returned
  when semantic check warning appears. (*)

**zone-reload** [*zone*...]
  Trigger a zone reload from a disk without checking its modification time. For
  secondary (slave) zone, the refresh from a primary (master) server is scheduled;
  for primary zone, the notification of secondary servers is scheduled. An open
  zone transaction will be aborted! If invoked with the force option, also zone
  modules will be re-loaded, but blocking mode might not work reliably. (#)

**zone-refresh** [*zone*...]
  Trigger a check for the zone serial on the zone's primary (master) server. If
  the primary server has a newer zone, a transfer is scheduled. This command is
  valid for secondary (slave) zones. (#)

**zone-retransfer** [*zone*...]
  Trigger a zone transfer from the zone's primary (master) server. The server
  doesn't check the serial of the primary server's zone. This command is valid
  for secondary (slave) zones. (#)

**zone-notify** [*zone*...]
  Trigger a NOTIFY message to all configured remotes. This can help in cases
  when previous NOTIFY had been lost or the secondary (slave) servers have been
  offline. (#)

**zone-flush** [*zone*...] [**+outdir** *directory*]
  Trigger a zone journal flush to the configured zone file. If an output
  directory is specified, the current zone is immediately dumped (in the
  blocking mode) to a zone file in the specified directory. (#)

**zone-backup** [*zone*...] **+backupdir** *directory* [**+journal**] [**+nozonefile**]
  Trigger a zone data and metadata backup to specified directory.
  Optional flag **+journal** backs up also zone journal, whereas **+nozonefile**
  avoids backing up current zone contents to a zone file. If zone flushing is disabled,
  original zone file is backed up instead. (#)

**zone-restore** [*zone*...] **+backupdir** *directory* [**+journal**] [**+nozonefile**]
  Trigger a zone data and metadata restore from specified backup directory.
  Optional flags are equivalent to **zone-backup**. (#)

**zone-sign** [*zone*...]
  Trigger a DNSSEC re-sign of the zone. Existing signatures will be dropped.
  This command is valid for zones with DNSSEC signing enabled. (#)

**zone-key-rollover** *zone* *key_type*
  Trigger immediate key rollover. Publish new key and start a key rollover,
  even when the key has a lifetime to go. Key type can be **ksk** (also for CSK)
  or **zsk**. This command is valid for zones with DNSSEC signing and automatic
  key management enabled. Note that complete key rollover consists of several steps
  and the blocking mode relates to the initial one only! (#)

**zone-ksk-submitted** *zone*...
  Use when the zone's KSK rollover is in submission phase. By calling this command
  the user confirms manually that the parent zone contains DS record for the new
  KSK in submission phase and the old KSK can be retired. (#)

**zone-freeze** [*zone*...]
  Trigger a zone freeze. All running events will be finished and all new and pending
  (planned) zone-changing events (load, refresh, update, flush, and DNSSEC signing)
  will be held up until the zone is thawed. (#)

**zone-thaw** [*zone*...]
  Trigger dismissal of zone freeze. (#)

**zone-read** *zone* [*owner* [*type*]]
  Get zone data that are currently being presented.

**zone-begin** *zone*...
  Begin a zone transaction.

**zone-commit** *zone*...
  Commit the zone transaction. All changes are applied to the zone.

**zone-abort** *zone*...
  Abort the zone transaction. All changes are discarded.

**zone-diff** *zone*
  Get zone changes within the transaction.

**zone-get** *zone* [*owner* [*type*]]
  Get zone data within the transaction.

**zone-set** *zone* *owner* [*ttl*] *type* *rdata*
  Add zone record within the transaction. The first record in a rrset
  requires a ttl value specified.

**zone-unset** *zone* *owner* [*type* [*rdata*]]
  Remove zone data within the transaction.

**zone-purge** *zone*... [*filter*...]
  Purge zone data, zone file, journal, timers, and/or KASP data of specified zones.
  Available filters are **+expire**, **+zonefile**, **+journal**, **+timers**,
  and **+kaspdb**. If no filter is specified, all filters are enabled.
  If the zone is no longer configured, add **+orphan** filter (zone file cannot
  be purged in this case). (#)

**zone-stats** *zone* [*module*\ [\ **.**\ *counter*\ ]]
  Show zone statistics counter(s). To print also counters with value 0, use
  force option.

**conf-init**
  Initialize the configuration database. If the database doesn't exist yet,
  execute this command as an intended user to ensure the server is permitted
  to access the database (e.g. *sudo -u knot knotc conf-init*). (*)

**conf-check**
  Check the server configuration. (*)

**conf-import** *filename*
  Import a configuration file into the configuration database. If the database
  doesn't exist yet, execute this command as an intended user to ensure the server
  is permitted to access the database (e.g. *sudo -u knot knotc conf-import ...*).
  Also ensure the server is not using the configuration database at the same time! (*)

**conf-export** [*filename*]
  Export the configuration database into a config file or stdout. (*)

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

Empty or **--** *zone* parameter means all zones or all zones with a transaction.

Use **@** *owner* to denote the zone name.

Type *item* parameter in the form of *section*\ [**[**\ *id*\ **]**\ ][**.**\ *name*].

(*) indicates a local operation which requires a configuration.

(\#) indicates an optionally blocking operation.

The *-b* and *-f* options can be placed right after the command name.

The *OK* response to triggering commands means that the command has been successfully sent
to the server. To verify if the operation succeeded it's necessary to check the server
log.

Interactive mode
................

The utility provides interactive mode with basic line editing functionality,
command completion, and command history.

Interactive mode behavior can be customized in `~/.editrc`. Refer to
:manpage:`editrc(5)` for details.

Command history is saved in `~/.knotc_history`.

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

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

Get the primary (master) servers for the example.com zone
.........................................................

::

  $ knotc conf-read 'zone[example.com].master'

Add example.org zone with a zonefile location
.............................................

::

  $ knotc conf-begin
  $ knotc conf-set 'zone[example.org]'
  $ knotc conf-set 'zone[example.org].file' '/var/zones/example.org.zone'
  $ knotc conf-commit

Get the SOA record for each configured zone
...........................................

::

  $ knotc zone-read -- @ SOA

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`, :manpage:`editrc(5)`.
