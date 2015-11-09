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
  Use a textual configuration file (default is :file:`@conf_dir@/knot.conf`).

**-C**, **--confdb** *directory*
  Use a binary configuration database.

**-s**, **--server** *server*
  Remote UNIX socket/IP address (default is :file:`@run_dir@/knot.sock`).

**-p**, **--port** *port*
  Remote server port (only for IP).

**-y**, **--key** [*alg*:]\ *name*:*key*
  Use the TSIG key specified on the command line (default algorithm is hmac-md5).

**-k**, **--keyfile** *file*
  Use the TSIG key stored in a file *file* to authenticate the request. The
  file must contain the key in the same format, which is accepted by the
  **-y** option.

**-f**, **--force**
  Force operation. Overrides some checks.

**-v**, **--verbose**
  Verbose mode. Print additional runtime information.

**-V**, **--version**
  Print the program version.

**-h**, **--help**
  Print help and usage.

Actions
.......

If the optional *zone* argument is not specified, the command is applied to all
zones.
Configuration *item* is in the *section*\ [**[**\ *id*\ **]**\ ][**.**\ *item*]
format.

**stop**
  Stop server (no-op if not running).

**reload** [*zone*...]
  Reload particular zones or reload the whole configuration and changed zones.

**flush** [*zone*...]
  Flush journal and update zone files.

**status**
  Check if server is running.

**zonestatus** [*zone*...]
  Show the status of listed zones.

**refresh** [*zone*...]
  Refresh slave zones. The **-f** flag forces re-transfer (zones must be specified).

**checkconf**
  Check the current configuration.

**checkzone** [*zone*...]
  Check zones.

**memstats** [*zone*...]
  Estimate memory consumption for zones.

**signzone** *zone*...
  Re-sign the zone (drop all existing signatures and create new ones).

**conf-import** *filename*
  Offline import of the configuration DB from a file. This is a
  potentially dangerous operation so the **-f** flag is required. Also the
  destination configuration DB must be specified via **-C**. Ensure the server
  is not running!

**conf-export** *filename*
  Export the configuration DB to a file. If no source configuration DB is
  specified, the temporary DB, corresponding to textual configuration file, is
  used.

**conf-desc** [*section*]
  Get the configuration section items list. If no section is specified,
  the list of sections is returned.

**conf-read** [*item*]
  Read from the current configuration DB.

**conf-begin**
  Begin a writing configuration DB transaction. Only one transaction can be
  opened at a time.

**conf-commit**
  Commit the current writing configuration DB transaction.

**conf-abort**
  Abort the current writing configuration DB transaction.

**conf-diff** [*item*]
  Get the difference between the active writing transaction and the current
  configuration DB. Requires active writing configuration DB transaction.

**conf-get** [*item*]
  Read from the active writing configuration DB transaction.
  Requires active writing configuration DB transaction.

**conf-set** *item* [*data*...]
  Write to the active writing configuration DB transaction.
  Requires active writing configuration DB transaction.

**conf-unset** [*item*] [*data*...]
  Delete from the active writing configuration DB transaction.
  Requires active writing configuration DB transaction.

Examples
--------

Setup a key file for remote control
...................................

::

  $ keymgr tsig generate knotc-key > knotc-key.conf

The generated key file contains a key in the server configuration format and
thus can be directly included into the server configuration file.

Knot DNS utilities accept one-line format which is included in the generated
key file on the first line as a comment. It can be extracted easily::

  $ head -1 knotc-key.conf | sed 's/^#\s*//' > knotc.key

Make sure the key file can be read only by the owner for security reasons.

Reload server remotely
......................

::

  $ knotc -s 127.0.0.1 -k knotc.key reload

Flush all zones locally
.......................

::

  $ knotc -c knot.conf flush

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
