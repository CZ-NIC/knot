.. highlight:: console

pykeymgr – Key management utility
=================================

Synopsis
--------

:program:`pykeymgr.py` [*global-options*] [*command*...] [*arguments*...]

Description
-----------

The :program:`pykeymgr` utility serves for key management in Knot DNS server.

Functions for DNSSEC keys and KASP (Key And Signature Policy)
management are provided.

The DNSSEC and KASP configuration is stored in a so called KASP database.
The databse is backed by LMDB.

Global options
..............

**-f**, **--force** 
  Skip some of consistency checks and continue with performed action with a warning.

**-h**, **--help**
  Print the program help.

Main commands
.............

**-z**, **--zones** *KASP_db_dir*
  List zones configured in KASP db together with key IDs of the DNSSEC keys
  belonging to each of the zones.

**-l**, **--list** *KASP_db_dir* *filter*
  List DNSSEC keys stored in the KASP db together with their parameters
  (key ID, key tag, is KSK ?, timers).

**-i**, **--import** *KASP_db_dir*
  Import the legacy JSON-format KASP database into the current LMDB-backed one.
  (You can import multiple databases at once by repeating this option.)

**-d**, **--ds** *KASP_db_dir* *zone_name* *key_spec*
  Calculate and print DS record for given key (used all SHA1, SHA256 and SHA384 digests).

**-s**, **--set** *KASP_db_dir* *zone_name* *key_spec* *param_name* *new_value*
  Set a key parameter to new value (mostly useful for timers).

Parameters
..........

*KASP_db_dir*
  A path to the KASP db. It is the directory where `data.mdb` and `lock.mdb`
  files are usually stored as well as legacy JSON configuration and `keys`
  subdirectory containing PEM files.

*zone_name*
  A name of the zone including trailing dot.

*key_spec*
  Either the key tag, key ID, or a prefix of key ID.

*filter*
  Following key attributes delimited by '&' character: all, ksk, zsk, published,
  active, retired. E.g. "all" means apply no filter; "zsk&active" filters the output
  to display just ZSKs which are active.

*param_name*
  A name for key parameter in question. Possible parameters are: `keytag`,
  `algorithm` (those two demand `--force` option), `isksk`, `created`,
  `publish`, `active`, `retire`, `remove`.

*new_value*
  New value for specified parameter: for `keytag` and `algorithm` - a number;
  for `isksk` - either "True" or "False"; for timers - either a number (= UNIX time)
  or "now[+-]<number><unit>" where `unit` is from ("y", "mo", "d", "h", "mi", <nothing=seconds>),
  e.g. "now-10", "now+2mo".

Examples
--------

1. Import legacy JSON-based KASP db from Knot 2.4.x after upgrade::

    $ pykemgr.py -i ${knot_data_dir}/keys

2. Set retire time for a specified key to 10 hours ahead::

    $ pykeymgr.py -s ${knot_data_dir}/keys example.zone. 5a701f91 retire now+10h

3. Display all published KSKs (for all zones)::

    $ pykeymgr.py -l ${knot_data_dir}/keys 'published&ksk'

4. Prepare DS records from key specified by tag (for all sha1, sha256, and sha384
   digest algorithms)::

    $ pykeymgr.py -d ${knot_data_dir}/keys 58041

See Also
--------

:rfc:`6781` - DNSSEC Operational Practices.

:manpage:`knot.conf(5)`,
:manpage:`knotc(8)`,
:manpage:`knotd(8)`.
