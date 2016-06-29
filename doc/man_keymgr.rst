.. highlight:: console

keymgr – Key management utility
===============================

Synopsis
--------

:program:`keymgr` [*global-options*] [*command*...] [*arguments*...]

:program:`keymgr` [*global-options*] [*command*...] **help**

Description
-----------

The :program:`keymgr` utility serves for key management in Knot DNS server.

Primarily functions for DNSSEC keys and KASP (Key And Signature Policy)
management are provided. However the utility also provides functions for
TSIG key generation.

The DNSSEC and KASP configuration is stored in a so called KASP database.
The database is simply a directory in the file-system containing files in the
JSON format.

The operations are organized into commands and subcommands. A command
specifies the operation to be performed with the KASP database. It is usually
followed by named arguments. The special command **help** can be used to list
available subcommands in that area. The listing of available command arguments
is not supported yet.

Command and argument names are parsed in a smart way. Only a beginning
of a name can be entered and it will be recognized. The specified part of
a name must be unique amongst the other names.

Global options
..............

**-c**, **--config** *file*
  Use a textual configuration file to get the KASP database location.

**-C**, **--confdb** *directory*
  Use a binary configuration database directory to get the KASP database location.

**-d**, **--dir** *path*
  Use a specified KASP database path to work with.

**-h**, **--help**
  Print the program help.

**-l**, **--legacy**
  Enable legacy mode. Zone, policy, and keystore configuration is stored
  in KASP database (not in server configuration).

**-V**, **--version**
  Print the program version.

KASP database location
......................

The location of the KASP database is determined as follows:

1. The path specified with **--dir**.
2. The path read from the server configuration specified with **--confdb** or
   **--config**.
3. The path read from the server default configuration database.
4. The path read from the server default configuration file.

In legacy mode, the path is determined as follows:

1. The path specified with **--dir**.
2. The path specified in the ``KEYMGR_DIR`` environment variable.
3. The current working dir.

Main commands
.............

**tsig** ...
  Operations with TSIG keys.

**zone** ...
  Operations with zones in the database. A zone holds assigned signing
  configuration and signing metadata.

Main commands (legacy)
......................

**init**
  Initialize new KASP database or upgrade existing one. The command is
  idempotent and therefore it is safe to be run multiple times.

  The command creates a default policy and default key store (both named
  *default*). In case of upgrade, existing objects are checked and any missing
  attributes are filled in.

**policy** ...
  Operations with KASP policies. A policy holds parameters that define the
  way how a zone is signed.

**keystore** ...
  Operations with key stores configured for the KASP database. A private key
  store holds private key material for zone signing separately from the zone
  metadata.

tsig commands
.............

**tsig** **generate** *name* [**algorithm** *id*] [**size** *bits*]
  Generate new TSIG key and print it on the standard output. The algorithm
  defaults to *hmac-sha256*. The default key size is determined optimally based
  on the selected algorithm.

  The generated key is printed out in the server configuration format to allow
  direct inclusion into the server configuration. The first line of the output
  contains a comment with the key in the one-line key format accepted by client
  utilities.

zone commands
.............

**zone** **key** **list** *zone-name* [**filter**]
  List key IDs and tags of zone keys.

**zone** **key** **show** *zone-name* *key*
  Show zone key details. The *key* can be a key tag or a key ID prefix.

**zone** **key** **ds** *zone-name* *key*
  Show DS records for a zone key. The *key* can be a key tag or a key ID prefix.

**zone** **key** **generate** *zone-name* [*key-parameter*...]
  Generate a new key for a zone.

**zone** **key** **import** *zone-name* *key-file*
  Import an existing key in the legacy format. The *key-file* suffix
  :file:`.private` or :file:`.key` is not required. A public key without
  a matching private key cannot be imported.

**zone** **key** **set** *zone-name* *key* [*key-parameter*...]
  Change a key parameter. Only key timing parameters can be changed.

Available *key-parameter*\ s:

  **algorithm** *id*
    Algorithm number or IANA mnemonic.

  **size** *bits*
    Size of the key in bits.

  **ksk**
    Set the DNSKEY SEP (Secure Entry Point) flag.

  **publish** *time*
    The time the key is published as a DNSKEY record.

  **active** *time*
    The time the key is started to be used for signing.

  **retire** *time*
   The time the key is stopped to be used for signing.

  **remove** *time*
    The time the key's DNSKEY is removed from the zone.

The *time* accepts YYYYMMDDHHMMSS format, unix timestamp, or offset from the
current time. For the offset, add **+** or **-** prefix and optionally a
suffix **mi**, **h**, **d**, **w**, **mo**, or **y**. If no suffix is specified,
the offset is in seconds.

zone commands (legacy)
......................

**zone** **add** *zone-name* [**policy** *policy-name*]
  Add a zone into the database. The policy defaults to 'default'.

**zone** **list** [*pattern*]
  List zones in the database matching the *pattern* as a substring.

**zone** **remove** *zone-name* [**force**]
  Remove a zone from the database. If some keys are currently active, the
  **force** argument must be specified.

**zone** **set** *zone-name* [**policy** *policy-name*]
  Change zone configuration. At the moment, only a policy can be changed.

**zone** **show** *zone-name*
  Show zone details.

policy commands (legacy)
........................

**policy** **list**
  List policies in the database.

**policy** **show** *policy-name*
  Show policy details.

**policy** **add** *policy-name* [*policy-parameter*...]
  Add a new policy into the database.

**policy** **set** *policy-name* [*policy-parameter*...]
  Change policy configuration.

**policy** **remove** *policy-name*
  Remove a policy from the database.
  **Note**, the utility does not check if the policy is used.

Available *policy-parameter*\ s:

  **algorithm** *id*
    DNSKEY algorithm number or IANA mnemonic.

  **dnskey-ttl** *seconds*
    TTL value for DNSKEY records.
    **Note**, the value is temporarily overridden by the SOA TTL.

  **ksk-size** *bits*
    Size of the KSK.

  **zsk-size** *bits*
    Size of the ZSK.

  **zsk-lifetime** *seconds*
    Period between ZSK publication and the next rollover initiation.

  **rrsig-lifetime** *seconds*
    Validity period of issued signatures.

  **rrsig-refresh** *seconds*
    Period before signature expiration when the signature will be refreshed.

  **nsec3** *enable*
    Specifies if NSEC3 will be used instead of NSEC.
    **Note**, currently unused (the setting is derived from NSEC3PARAM presence
    in the zone).

  **soa-min-ttl** *seconds*
    SOA Minimum TTL field.
    **Note**, Knot DNS overwrites the value with the real used value.

  **zone-max-ttl** *seconds*
    Max TTL in the zone.
    **Note**, Knot DNS will determine the value automatically in the future.

  **delay** *seconds*
    Zone signing and data propagation delay. The value is added for safety to
    timing of all rollover steps.

  **manual** *enable*
    Enable manual key management. If enabled, no keys will be generated or
    rolled automatically.

  **keystore** *name*
    Name of the key store to be used for private key material.

keystore commands (legacy)
..........................

**keystore** **list**
  List names of configured key stores.

**keystore** **show** *name*
  Show configuration of a key store named *name* and list key IDs of private
  key material present in that key store.

**keystore** **add** *name* [**backend** *backend*] [**config** *config*]
  Configure new key store. The *name* is a unique key store identifier. The
  *backend* and backend-specific configuration string *config* determine where
  the private key material will be physically stored.

Supported key store backends:

  **pkcs8** (default)
    The backend stores private key material in unencrypted X.509 PEM files
    in a directory specified as the backend configuration string. The path
    can be specified relatively to the KASP database location.

  **pkcs11**
    The backend stores private key material in a cryptographic token accessible
    via the PKCS #11 interface. The configuration string consists of a token
    PKCS #11 URL and PKCS #11 module path separated by the space character.

    The format of the PKCS #11 URL is described in :rfc:`7512`. If the token
    is protected by a PIN, make sure to include *pin-value* or *pin-source*
    attribute in the URL.

    The PKCS #11 module path can be an absolute path or just a module name. In
    the later case, the module is looked up in the default modules location.

Examples
--------

1. Generate two RSA-SHA-256 signing keys. The first key will be used as a KSK,
   the second one as a ZSK::

    $ keymgr zone key generate example.com algorithm rsasha256 size 2048 ksk
    $ keymgr zone key generate example.com algorithm rsasha256 size 1024

2. Import a key in legacy format. The used algorithm must match with the one
   configured in the policy::

    $ keymgr zone key import example.com Kexample.com+010+12345.private

3. Generate a TSIG key named *operator.key*::

    $ keymgr tsig generate operator.key algorithm hmac-sha512

See Also
--------

:rfc:`6781` - DNSSEC Operational Practices.

:manpage:`knot.conf(5)`,
:manpage:`knotc(8)`,
:manpage:`knotd(8)`.
