.. highlight:: console

keymgr – Key management utility
===============================

Synopsis
--------

:program:`keymgr` *basic_option* [*parameters*...]

:program:`keymgr` [*config_option* *config_storage*] *zone* *command* *argument*...

Description
-----------

The :program:`keymgr` utility serves for manual key management in Knot DNS server.

Functions for DNSSEC keys and KASP (Key And Signature Policy)
management are provided.

The DNSSEC and KASP configuration is stored in a so called KASP database.
The database is backed by LMDB.

Basic options
.............

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

**-t**, **--tsig** *tsig_name* [*tsig_algorithm*] [*tsig_bits*]
  Generates a TSIG key. TSIG algorithm can be specified by string (default: hmac-sha256),
  bit length of the key by number (default: optimal length given by algorithm). The generated 
  TSIG key is only displayed on `stdout`: the command does not create a file, nor include the
  key in a keystore.

Config options
..............

**-c**, **--config** *file*
  Use a textual configuration file (default is :file:`@config_dir@/knot.conf`).

**-C**, **--confdb** *directory*
  Use a binary configuration database directory (default is :file:`@storage_dir@/confdb`).
  The default configuration database, if exists, has a preference to the default
  configuration file.

**-d**, **--dir** *path*
  Use specified KASP database path and default configuration.

Commands
........

**list** [*timestamp_format*]
  Prints the list of key IDs and parameters of keys belonging to the zone.

**generate** [*arguments*...]
  Generates new DNSSEC key and stores it in KASP database. Prints the key ID.
  This action takes some number of arguments (see below). Values for unspecified arguments are taken
  from corresponding policy (if *-c* or *-C* options used) or from Knot policy defaults.

**import-bind** *BIND_key_file*
  Imports a BIND-style key into KASP database (converting it to PEM format).
  Takes one argument: path to BIND key file (private or public, but both MUST exist).

**import-pub** *BIND_pubkey_file*
  Imports a public key into KASP database. This key won't be rollovered nor used for signing.
  Takes one argument: path to BIND public key file.

**import-pem** *PEM_file* [*arguments*...]
  Imports a DNSSEC key from PEM file. The key parameters (same as for the generate action) need to be
  specified (mainly algorithm, timers...) because they are not contained in the PEM format.

**import-pkcs11** *key_id* [*arguments*...]
  Imports a DNSSEC key from PKCS #11 storage. The key parameters (same as for the generate action) need to be
  specified (mainly algorithm, timers...) because they are not available. In fact, no key
  data is imported, only KASP database metadata is created.

**nsec3-salt** [*new_salt*]
  Prints the current NSEC3 salt used for signing. If *new_salt* is specified, the salt is overwritten.
  The salt is printed and expected in hexadecimal, or dash if empty.

**set** *key_spec* [*arguments*...]
  Changes a timing argument (or ksk/zsk) of an existing key to a new value. *Key_spec* is either the
  key tag or a prefix of the key ID; *arguments* are like for **generate**, but just the related ones.

**ds** [*key_spec*]
  Generate DS record (all digest algorithms together) for specified key. *Key_spec*
  is like for **set**, if unspecified, all KSKs are used.

**dnskey** [*key_spec*]
  Generate DNSKEY record for specified key. *Key_spec*
  is like for **ds**, if unspecified, all KSKs are used.

**delete** *key_spec*
  Remove the specified key from zone. If the key was not shared, it is also deleted from keystore.

**share** *key_ID*
  Import a key (specified by full key ID) from another zone as shared. After this, the key is
  owned by both zones equally.

Commands related to Offline KSK feature
.......................................

**pregenerate** *timestamp*
  Pre-generate ZSKs for use with offline KSK, for the specified period starting from now.

**show-offline** *timestamp*
  Print pre-generated offline key-related records for specified timestamp.

**del-offline** *timestamp-from* *timestamp-to*
  Delete pre-generated offline key-related records in specified time interval.

**del-all-old**
  Delete old keys that are in state 'removed'.

**generate-ksr** *timestamp*
  Print to stdout KeySigningRequest based on pre-generated ZSKs for specified period.

**sign-ksr** *ksr_file*
  Read KeySigingRequest from a text file, sign it using local keyset and print SignedKeyResponse to stdout.

**import-skr** *skr_file*
  Read SignedKeyResponse from a text file and import the signatures for later use in zone. (The signatures
  are not at all checked at import time, but they will be ignored at signing time if invalid.)

Generate arguments
..................

Arguments are separated by space, each of them is in format 'name=value'.

**algorithm**
  Either an algorithm number (e.g. 14), or text name without dashes (e.g. ECDSAP384SHA384).

**size**
  Key length in bits.

**ksk**
  If set to **yes**, the key will be used for signing DNSKEY rrset. The generated key will also
  have the Secure Entry Point flag set to 1.

**zsk**
  If set to **yes**, the key will be used for signing zone (except DNSKEY rrset). This flag can
  be set concurrently with the **ksk** flag.

**sep**
  Overrides the standard setting of the Secure Entry Point flag for the generated key.

The following arguments are timestamps of key lifetime (see :ref:`DNSSEC Key states`):

**created**
  Key created.

**pre_active**
  Key started to be used for signing, not published (only for algorithm rollover).

**publish**
  Key published.

**ready**
  Key used for signing and submitted to the parent zone (only for KSK).

**active**
  Key used for signing.

**post_active**
  Key still used for singing, but another key is active (only for KSK).

**retire_active**
  Key no longer published, but still used for signing (only for algorithm rollover).

**retire**
  Key still published, but no longer used for signing.

**remove**
  Key deleted.

Timestamps
..........

0
  Zero timestamp means infinite future.

*UNIX_time*
  Positive number of seconds since 1970 UTC.

*YYYYMMDDHHMMSS*
  Date and time in this format without any punctuation.

*relative_timestamp*
  A sign character (**+**, **-**), a number, and an optional time unit
  (**y**, **mo**, **d**, **h**, **mi**, **s**). The default unit is one second.
  E.g. +1mi, -2mo.

Output timestamp formats
........................

(none)
  The timestamps are printed as UNIX timestamp.

**human**
  The timestamps are printed relatively to now using time units (e.g. -2y5mo, +1h13s).

**iso**
  The timestamps are printed in the ISO8601 format (e.g. 2016-12-31T23:59:00).

Examples
--------

1. Generate new TSIG key::

    $ keymgr -t my_name hmac-sha384

2. Generate new DNSSEC key::

    $ keymgr example.com. generate algorithm=ECDSAP256SHA256 size=256 \
      ksk=true created=1488034625 publish=20170223205611 retire=+10mo remove=+1y

3. Import a DNSSEC key from BIND::

    $ keymgr example.com. import-bind ~/bind/Kharbinge4d5.+007+63089.key

4. Configure key timing::

    $ keymgr example.com. set 4208 active=+2mi retire=+4mi remove=+5mi

5. Share a KSK from another zone::

    $ keymgr example.com. share e687cf927029e9db7184d2ece6d663f5d1e5b0e9

See Also
--------

:rfc:`6781` - DNSSEC Operational Practices.
:rfc:`7583` - DNSSEC Key Rollover Timing Considerations.

:manpage:`knot.conf(5)`,
:manpage:`knotc(8)`,
:manpage:`knotd(8)`.
