.. highlight:: console

knotc -- Knot DNS control utility
=================================

Synopsis
--------

:program:`knotc` [*parameters*] *action* [*action_args*]

Description
-----------

Parameters
..........

**-c**, **--config** *file*
  Use textual configuration file (default is :file:`@conf_dir@/knot.conf`).

**-C**, **--confdb** *directory*
  Use binary configuration database.

**-s**, **--server** *server*
  Remote UNIX socket/IP address (default is :file:`@run_dir@/knot.sock`).

**-p**, **--port** *port*
  Remote server port (only for IP).

**-y**, **--key** [*alg*:]\ *name*:*key*
  Use TSIG key specified on the command line (default algorithm is hmac-md5).

**-k**, **--keyfile** *file*
  Use TSIG key stored in a file *file* to authenticate the request. The
  file must contain the key in the same format, which is accepted by the
  **-y** option.

**-f**, **--force**
  Force operation. Overrides some checks.

**-v**, **--verbose**
  Verbose mode. Print additional runtime information.

**-V**, **--version**
  Print program version.

**-h**, **--help**
  Print help and usage.

Actions
.......

If an optional *zone* argument is not specified, the command is applied to all
zones.

**stop**
  Stop server (no-op if not running).

**reload** [*zone*...]
  Reload particular zones or reload whole configuration and changed zones.

**flush** [*zone*...]
  Flush journal and update zone files.

**status**
  Check if server is running.

**zonestatus** [*zone*...]
  Show status of configured zones.

**refresh** [*zone*...]
  Refresh slave zones. Flag **-f** forces re-transfer (zones must be specified).

**checkconf**
  Check current configuration.

**checkzone** [*zone*...]
  Check zones.

**memstats** [*zone*...]
  Estimate memory consumption for zones.

**signzone** *zone*...
  Resign the zone (drop all existing signatures and create new ones).

**import** *file*
  Import configuration database from file. This is potentially dangerous
  operation, thus flag **-f** is required.

**export** *file*
  Export configuration database to file.

Examples
--------

Setup a keyfile for remote control
..................................

1. Generate key::

     $ dnssec-keygen -a hmac-md5 -b 256 -n HOST knotc-key

2. Extract secret in base64 format and create keyfile::

     $ echo "knotc-key hmac-md5 <secret>" > knotc.key

Make sure the key can be read/written only by the owner for security reasons.

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
