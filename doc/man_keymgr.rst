.. highlight:: console

keymgr – Key management utility
===============================

Synopsis
--------

:program:`keymgr` *basic_option* [*parameters*...]

:program:`keymgr` *config_option* *config_storage* *zone_name* *action* *parameters*...

Description
-----------

The :program:`keymgr` utility serves for key management in Knot DNS server.

Functions for DNSSEC keys and KASP (Key And Signature Policy)
management are provided.

The DNSSEC and KASP configuration is stored in a so called KASP database.
The databse is backed by LMDB.

Basic options
.............

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

**-t** [*tsig_algorithm*] [*tsig_bits*]
  Generates TSIG key. TSIG algorithm can be specified by string (default: hmac-sha256),
  bit length of the key by number (default: optimal length given by algorithm).

Config options
..............

**-d**
  Use KASP database directory specified by config_storage.

**-c**
  Determine KASP database location from Knot DNS configuration file, specified
  by config_storage.

**-C**
  Determine KASP database location from Knot DNS configuration database,
  specified by config_storage.

Actions
.......

**list**
  Prints the list of key IDs and parameters of keys belonging to the zone.

**generate** [*arguments*...]
  Generates new DNSSEC key and stores it in KASP database. Prints the key ID.
  This action takes some number of arguments (see below). Values for unspecified arguments are taken
  from corresponding policy (if *-c* or *-C* options used) or from Knot policy defaults.

**import-bind** *BIND_key_file*
  Imports a BIND-style key into KASP database (converting it to PEM format).
  Takes one argument: path to BIND key file (private or public, but both MUST exist).

**set** *key_spec* [*arguments*...]
  Changes a timing argument of an existing key to new timestamp. *Key_spec* is either the
  key tag or a prefix of key ID; *arguments* are like for **generate**, but just
  timing-related ones.

**ds** *key_spec*
  Generate DS record (all digest algorithms together) from specified key. *Key_spec*
  is like for **set**.

**delete** *key_spec*
  Remove the specified key from zone. If the key was not shared, it is also deleted from keystore.

**share** *key_ID*
  Import a key (specified by full key ID) from another zone as shared. After this, the key is
  owned by both zones equally.

Generate arguments
..................

Arguments are separated by space, each of them is in format 'name=value'.

**algorithm**
  Either an algorithm number (e.g. 14), or text name without dashes (e.g. ECDSAP384SHA384).

**size**
  Key length in bits.

**ksk**
  Either 'true' (KSK will be generated) or 'false' (ZSK wil be generated).

**created**
  Timestamp of key creation.

**publish**
  Timestamp for key to be published.

**active**
  Timestamp for key to be activated.

**retire**
  Timestamp for key to be de-activated.

**remove**
  Timestamp for key ot be deleted.

Timestamps
..........

*UNIX_time*
  Positive number of seconds since 1970.

*YYYYMMDDHHMMSS*
  Date and time in this format without any punctuation.

*relative_timestamp*
  The word "now" followed by sign (+, -), a number and a shortcut for time unit
  (y, mo, d, h, mi, (nothing = seconds)), e.g. now+1mi, now-2mo, now+10,
  now+0, now-1y, ...

Examples
--------

1. Generate TSIG key::

    $ keymgr -t my_name hmac-sha384

2. Import a key from BIND::

    $ keymgr -d ${knot_data_dir}/keys example.com. import-bind ~/bind/Kharbinge4d5.+007+63089.key

3. Generate new key::

    $ keymgr -c ${knot_data_dir}/knot.conf example.com. generate algorithm=ECDSAP256SHA256 size=256 \
      ksk=true created=1488034625 publish=20170223205611 retire=now+10mo remove=now+1y

4. Configure key timing::

    $ keymgr -d ${knot_data_dir}/keys test.test. set 4208 active=t+2mi retire=t+4mi remove=t+5mi

5. Share a KSK from another zone::

    $ keymgr -c ${knot_data_dir}/knot.conf test.test. share e687cf927029e9db7184d2ece6d663f5d1e5b0e9

See Also
--------

:rfc:`6781` - DNSSEC Operational Practices.

:manpage:`knot.conf(5)`,
:manpage:`knotc(8)`,
:manpage:`knotd(8)`.
