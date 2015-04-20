keymgr -- DNSSEC key management utility
=======================================

Synopsis
--------

:program:`keymgr` [*global-options*] [*command*...] [*arguments*...]

:program:`keymgr` [*global-options*] [*command*...] **help**

Description
-----------

The :program:`keymgr` utility serves for DNSSEC keys and Key And Signature
Policy (KASP) management in Knot DNS server. The configuration is stored in a
so called KASP database. The database is simply a directory on a file
file-system containing files in JSON format.

The operations are organized into commands and subcommands. The command
specifies an operation to be performed with the KASP database. It is usually
followed by named arguments. A special command **help** can be used to list
available subcommands at that position. Listing of available command arguments
is not supported yet.

The command and argument names and parsed in a smart way. Only a beginning
of the name can be specified and will be recognized. The specified part must
be unique amongst the other names.

Global options
..............

**--dir** *path*
  The location of the KASP database to work with. Defaults to current working
  directory.

Main commands
.............

**init**
  Initialize new KASP database.

**zone** ...
  Operations with zones in the database. A zone holds assigned signing
  configuration and signing metadata.

**policy** ...
  Operations with KASP policies. The policy holds parameters that define the
  way how a zone is signed.

**keystore** ...
  Operations with private key store content. The private key store holds
  private key material separately from zone metadata.

zone commands
.............

**zone** **add** *name* [**policy** *policy*\ \|none]
  Add a new zone into the database. The **policy** defaults to none.

**zone** **list** [*search*]
  List matching zones in the database.

**zone** **remove** *name* [**force**]
  Remove a zone from the database. If some keys are currently active, the
  **force** argument must be specified.

**zone** **show** *name*
  Show zone details.

**zone** **key** ...
  Operations with zone keys.

**zone** **set** *name* [**policy** *policy*\ \|none]
  Change zone parameters.

zone key commands
.................

**zone** **key** **list** *zone*
  List zone key IDs and tags.

**zone** **key** **show** *zone* *key*
  Show zone key details. The *key* can be a key tag or a key ID prefix.

**zone** **key** **generate** *zone* [*key-attribute*...]
  Generate a new key for a zone.

**zone** **key** **set** *zone* *key* [*key-attribute*...]
  Change a key parameter. Only key timing parameters can be changed.

**zone** **key** *import* *zone* *filename*
  Import existing key in the legacy format. The file suffix :file:`.private`
  or :file:`.key` is automatically removed if necessary. Currently only keys
  with private key can be imported.

Available *key-attribute*\ s:

  **algorithm** *id*
    Algorithm number or IANA mnemonic.

  **size** *size*
    Size of the key in bits.

  **ksk**
    Set the DNSKEY SEP (Secure Entry Point) flag.

  **publish** *time*
    The time the key is publish as a DNSKEY record.

  **active** *time*
    The time the key is started to be used for signing.

  **retire** *time*
   The time the key is stopped to be used for signing.

  **remove** *time*
    The time the key's DNSKEY is removed from the zone.

The *time* accepts YYYYMMDDHHMMSS format, unix timestamp, or offset from the
current time. For the offset, add + or - prefix and optionally a suffix mi, h,
d, w, mo, or, y. If no suffix is specified, the offset is in seconds.

zone policy commands
....................

**zone** **policy** **list**
  List policies in the database.

**zone** **policy** **show** *name*
  Show policy details.

**zone** **policy** **add** *name* [*policy-attribute*...]
  Add a new policy into the database.

**zone** **policy** **set** *name* [*policy-attribute*...]
  Updates the policy settings. The accepted options are the same as for *add*.

**zone** **policy** **remove** *name*
  Remove policy from the database.
  **Note**, the utility does not check, if the policy is used.

Available *policy-attribute*\ s:

  **algorithm** *id*
    DNSKEY algorithm number or IANA mnemonic.

  **dnskey-ttl** *interval*
    TTL value for DNSKEY records.
    **Note**, the value is temporarily overridden by the SOA TTL**.

  **ksk-size** *size*
    Set size of the KSK in bits.

  **zsk-size** *size*
    Set size of the ZSK in bits.

  **zsk-lifetime** *interval*
    Interval, after which the ZSK rollover will be initiated.

  **rrsig-lifetime** *interval*
    Lifetime of issued RRSIGs.

  **rrsig-refresh** *seconds*
    How long before RRSIG expiration it will be refreshed.

  **nsec3** *enable*
    Specifies if NSEC3 will be used instead of NSEC.
    **Note**, currently unused (the setting is derived from NSEC3PARAM presence
    in the zone.)

  **soa-min-ttl** *interval*
    SOA Minimum TTL field.
    **Note**, Knot DNS overwrites the value with the real used value.

  **zone-max-ttl** *interval*
    Max TTL in the zone.
    **Note**, Knot DNS will determine the value automatically in the future.

  **delay** *interval*
    Zone signing and data propagation delay. The value is added for safety to
    timing of all rollover steps.

zone keystore commands
......................

The key store functionality is limited at the moment. Only one file-based key
store is supported. This command is subject to change.

**zone** **keystore** **list**
  List private keys in the key store.

Examples
--------

1. Initialize new KASP database, add a policy named *default* with default
   parameters, and add a zone *example.com*. The zone will use the created
   policy::

   $ keymgr init
   $ keymgr policy add default
   $ keymgr zone add example.com policy default

2. List zones containing *.com* substring::

   $ keymgr zone list .com

3. Add a testing policy *lab* with rapid key rollovers. Apply the policy to an
   existing zone::

   $ keymgr policy add lab rrsig-lifetime 300 rrsig-refresh 150 zsk-lifetime 600 delay 10
   $ keymgr zone set example.com policy lab

4. Add an existing and already secured zone. Let the keys be managed by the
   KASP. Make sure to import all used keys. Also the used algorithm must match
   with the one configured in the policy::

   $ keymgr zone add example.com policy default
   $ keymgr zone key import Kexample.com+010+12345.private
   $ keymgr zone key import Kexample.com+010+67890.private

5. Disable automatic key management for a secured zone::

   $ keymgr zone set example.com policy none

6. Add a zone to be signed with manual key maintenance. Generate one ECDSA
   signing key. The Single-Type Signing scheme will be used::

   $ keymgr zone add example.com policy none
   $ keymgr zone key gen algo 13 size 256

Legacy utilities
----------------

The :program:`keymgr` utility provides partial support for legacy key format.

The following table shows commands equivalent to BIND utilities:

================   ========================
**BIND**           **Knot DNS**
================   ========================
dnssec-keygen      keymgr zone key generate
dnssec-settime     keymgr zone key set
dnssec-dsfromkey   N/A
dnssec-revoke      N/A
nsec3hash          knsec3hash
================   ========================

See Also
--------

:rfc:`6781` - DNSSEC Operational Practices.

:manpage:`knot.conf(5)`,
:manpage:`knotc(8)`,
:manpage:`knotd(8)`.
