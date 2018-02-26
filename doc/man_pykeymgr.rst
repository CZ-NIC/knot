.. highlight:: console

pykeymgr – Key management utility
=================================

Synopsis
--------

:program:`pykeymgr` [*global-options*] [*command*...] [*arguments*...]

Description
-----------

The :program:`pykeymgr` utility serves for key management in Knot DNS server.

Functions for DNSSEC keys and KASP (Key And Signature Policy)
management are provided.

The DNSSEC and KASP configuration is stored in a so called KASP database.
The database is backed by LMDB.

The utility requires installed python LMDB module, installed e.g. by::

    $ pip install lmdb

Global options
..............

**-f**, **--force** 
  Skip some of consistency checks and continue with performed action with a warning.

**-h**, **--help**
  Print the program help.

Main commands
.............

**-i**, **--import** *KASP_db_dir*
  Import the legacy JSON-format KASP database into the current LMDB-backed one.
  (You can import multiple databases at once by repeating this option.)

Parameters
..........

*KASP_db_dir*
  A path to the KASP db. It is the directory where `data.mdb` and `lock.mdb`
  files are usually stored as well as legacy JSON configuration and `keys`
  subdirectory containing PEM files.

Examples
--------

1. Import legacy JSON-based KASP db from Knot 2.4.x after upgrade::

    $ pykemgr -i ${knot_data_dir}/keys

See Also
--------

:rfc:`6781` - DNSSEC Operational Practices.

:manpage:`knot.conf(5)`,
:manpage:`knotc(8)`,
:manpage:`knotd(8)`.
