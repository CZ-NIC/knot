.. highlight:: none

``keymgr`` – Key management utility
===================================

Synopsis
--------

:program:`keymgr` [*config_option*] [*options*] *zone_name* *command*

:program:`keymgr` [*config_option*] [*options*] *keystore_id* *command*

:program:`keymgr` [*config_option*] [-j] **-l**

:program:`keymgr` **-t** *parameter*...

Description
-----------

The :program:`keymgr` utility serves for manual key management in Knot DNS server.

Functions for DNSSEC keys and KASP (Key And Signature Policy)
management are provided.

The DNSSEC and KASP configuration is stored in a so called KASP database.
The database is backed by LMDB.

Parameters
..........

*zone_name*
  Name of the zone the command is executed for.

Config options
..............

**-c**, **--config** *file*
  Use a textual configuration file (default is :file:`@config_dir@/knot.conf`).

**-C**, **--confdb** *directory*
  Use a binary configuration database directory (default is :file:`@storage_dir@/confdb`).
  The default configuration database, if exists, has a preference to the default
  configuration file.

**-D**, **--dir** *path*
  Use specified KASP database path and default configuration.

Options
.......

**-t**, **--tsig** *tsig_name* [*tsig_algorithm* [*tsig_bits*]]
  Generates a TSIG key for the given name. Optionally the key algorithm can
  be specified by its :ref:`name<key_algorithm>` (default: hmac-sha256) and
  a bit length of the key (default: optimal length given by algorithm).
  The generated TSIG key is only displayed on `stdout`:
  the command does not create a file, nor include the key in a keystore.

**-e**, **--extended**
  Extended output (listing of keys with full description).

**-j**, **--json**
  Print the zones or keys in JSON format.

**-l**, **--list**
  Print the list of zones that have at least one key stored in the configured KASP
  database.

**-x**, **--mono**
  Don't generate colorized output.

**-X**, **--color**
  Force colorized output in the normal mode.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version. The option **-VV** makes the program
  print the compile time configuration summary.

.. NOTE::
   Keymgr runs with the same user privileges as configured for :doc:`knotd<man_knotd>`.
   For example, if keymgr is run as ``root``, but the configured :ref:`user<server_user>`
   is ``knot``, it won't be able to read files (PEM files, KASP database, ...) readable
   only by ``root``.

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
  Imports a public key into KASP database. This key won't be rolled over nor used for signing.
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

**local-serial** [*new_serial*]
  Print SOA serial stored in KASP database when using on-secondary DNSSEC signing.
  If *new_serial* is specified, the serial is overwritten. After updating the serial, expire the zone
  (**zone-purge +expire +zonefile +journal**) if the server is running, or remove corresponding zone file
  and journal contents if the server is stopped.

**master-serial** [*new_serial*]
  Print SOA serial of the remote master stored in KASP database when using on-secondary DNSSEC signing.
  If *new_serial* is specified, the serial is overwritten (not recommended).

**set** *key_spec* [*arguments*...]
  Changes a timing argument (or ksk/zsk) of an existing key to a new value. *Key_spec* is either the
  key tag or a prefix of the key ID, with an optional *[id=|keytag=]* prefix; *arguments* 
  are like for **generate**, but just the related ones.

**ds** [*key_spec*]
  Generate DS record (all digest algorithms together) for specified key. *Key_spec*
  is like for **set**, if unspecified, all KSKs are used.

**dnskey** [*key_spec*]
  Generate DNSKEY record for specified key. *Key_spec*
  is like for **ds**, if unspecified, all KSKs are used.

**delete** *key_spec*
  Remove the specified key from zone. If the key was not shared, it is also deleted from keystore.

**share** *key_ID* *zone_from*
  Import a key (specified by full key ID) from another zone as shared. After this, the key is
  owned by both zones equally.

Keystore commands
.................

**keystore-test**
  Conduct some tests on the specified keystore. For each algorithm, key generation,
  import, removal, and use (signing and verification) are tested.
  Use a configured *keystore_id* or **-** for the default.

**keystore-bench** [*num_threads*]
  Conduct a signing benchmark on the specified keystore.
  Random blocks of data are signed by the selected number of threads
  (default is 1) in a loop, and the average number of signing operations per
  second for each algorithm is returned.
  Use a configured *keystore_id* or **-** for the default.

Commands related to Offline KSK feature
.......................................

**pregenerate** [*timestamp-from*] *timestamp-to*
  Pre-generate ZSKs for use with offline KSK, for the specified period starting from now or specified time.
  This function also applies to non-offline KSK keys.

**show-offline** [*timestamp-from*] [*timestamp-to*]
  Print pre-generated offline key-related records for specified time interval. If *timestamp_to*
  is omitted, it will be to infinity. If *timestamp-from* is omitted, it will start from the
  beginning.

**del-offline** *timestamp-from* *timestamp-to*
  Delete pre-generated offline key-related records in specified time interval.

**del-all-old**
  Delete old keys that are in state 'removed'. This function also applies to
  non-offline KSK keys.

**generate-ksr** [*timestamp-from*] *timestamp-to*
  Print to stdout KeySigningRequest based on pre-generated ZSKs for specified time period.
  If *timestamp-from* is omitted, timestamp of the last offline records set is used
  or now if no records available.

**sign-ksr** *ksr_file*
  Read KeySigningRequest from a text file, sign it using local keyset and print SignedKeyResponse to stdout.

**validate-skr** *skr_file*
  Read SignedKeyResponse from a text file and validate the RRSIGs in it if not corrupt.

**import-skr** *skr_file*
  Read SignedKeyResponse from a text file and import the signatures for later use in zone. If some
  signatures have already been imported, they will be deleted for the period from beginning of the SKR
  to infinity.

Generate arguments
..................

Arguments are separated by space, each of them is in format 'name=value'. A *(bool)* argument
accepts values **yes** or **no**. If the value is omitted, it's interpreted as **yes**.

**algorithm**
  Either an algorithm number (e.g. 14) or :ref:`algorithm name<policy_algorithm>`
  (e.g. ecdsap256sha256).

**size**
  Key length in bits.

**ksk**
  *(bool)* The key will be used for signing DNSKEY rrset. The generated key will also
  have the Secure Entry Point flag set to 1.

**zsk**
  *(bool)* The key will be used for signing zone (except DNSKEY rrset). This flag can
  be set concurrently with the **ksk** flag (for a CSK key).

**sep**
  *(bool)* Overrides the standard setting of the Secure Entry Point flag.

**for-later**
  *(bool)* The key will be determined for later use. It means once a new key ought
  to be generated, this one will be used instead if the key type and algorithm match.

The following arguments are timestamps of key lifetime (see :ref:`DNSSEC Key states`):

**pre_active**
  Key started to be used for signing, not published (only for algorithm rollover).

**publish**
  Key published.

**ready**
  Key is waiting for submission (only for KSK).

**active**
  Key used for signing.

**retire_active**
  Key still used for signing, but another key is active (only for KSK or algorithm rollover).

**retire**
  Key still published (only if ZSK), but no longer used for signing.

**post_active**
  Key no longer published, but still used for signing (only for algorithm rollover).

**revoke**
  Key revoked according to :rfc:`5011` trust anchor roll-over.

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

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

Examples
--------

1. Generate new TSIG key::

    $ keymgr -t my_name hmac-sha384

2. Generate new DNSSEC key::

    $ keymgr example.com. generate algorithm=ECDSAP256SHA256 size=256 \
      ksk=true created=1488034625 publish=20170223205611 retire=+10mo remove=+1y

3. Import a DNSSEC key from BIND::

    $ keymgr example.com. import-bind ~/bind/Kharbinge4d5.+007+63089.key

4. Import a CSK DNSSEC key from a PEM file::

    $ keymgr example.com. import-pem 085d3890e8c22d854586678d9263933f2d02d795.pem ksk=yes zsk=yes

5. Configure key timing::

    $ keymgr example.com. set 4208 active=+2mi retire=+4mi remove=+5mi

6. Share a KSK from another zone::

    $ keymgr example.com. share e687cf927029e9db7184d2ece6d663f5d1e5b0e9 another-zone.com.

See Also
--------

:rfc:`6781` - DNSSEC Operational Practices.
:rfc:`7583` - DNSSEC Key Rollover Timing Considerations.

:manpage:`knot.conf(5)`,
:manpage:`knotc(8)`,
:manpage:`knotd(8)`.
