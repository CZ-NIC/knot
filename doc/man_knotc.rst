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

**import** *file*
  Import a configuration database from file. This is a potentially dangerous
  operation, thus the **-f** flag is required.

**export** *file*
  Export the configuration database to a file.

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

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
