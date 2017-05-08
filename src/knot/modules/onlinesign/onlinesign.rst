.. _mod-onlinesign:

``onlinesign`` — Online DNSSEC signing
======================================

The module provides online DNSSEC signing. Instead of pre-computing the zone
signatures when the zone is loaded into the server or instead of loading an
externally signed zone, the signatures are computed on-the-fly during
answering.

The main purpose of the module is to enable authenticated responses with
zones which use other dynamic module (e.g., automatic reverse record
synthesis) because these zones cannot be pre-signed. However, it can be also
used as a simple signing solution for zones with low traffic and also as
a protection against zone content enumeration (zone walking).

In order to minimize the number of computed signatures per query, the module
produces a bit different responses from the responses that would be sent if
the zone was pre-signed. Still, the responses should be perfectly valid for
a DNSSEC validating resolver.

Differences from statically signed zones:

* The NSEC records are constructed as Minimally Covering NSEC Records
  (see Appendix A in :rfc:`7129`). Therefore the generated domain names cover
  the complete domain name space in the zone's authority.

* NXDOMAIN responses are promoted to NODATA responses. The module proves
  that the query type does not exist rather than that the domain name does not
  exist.

* Domain names matching a wildcard are expanded. The module pretends and proves
  that the domain name exists rather than proving a presence of the wildcard.

Records synthesized by the module:

* DNSKEY record is synthesized in the zone apex and includes public key
  material for the active signing key.

* NSEC records are synthesized as needed.

* RRSIG records are synthesized for authoritative content of the zone.

Known issues:

* The delegations are not signed correctly.

* Some CNAME records are not signed correctly.

* The automatic policy-based key rotation does not work. The rotation events are
  invoked just at server (re)load.

Limitations:

* Online-sign module always enforces Single-Type Signing scheme.

* Only one active signing key can be used.

* Key rollover is not possible.

* The NSEC records may differ for one domain name if queried for different
  types. This is an implementation shortcoming as the dynamic modules
  cooperate loosely. Possible synthesis of a type by other module cannot
  be predicted. This dissimilarity should not affect response validation,
  even with validators performing `aggressive negative caching
  <https://datatracker.ietf.org/doc/draft-fujiwara-dnsop-nsec-aggressiveuse/>`_.

* The NSEC proofs will work well with other dynamic modules only if the
  modules synthesize only A and AAAA records. If synthesis of other type
  is required, please, report this information to Knot DNS developers.

Example
-------

* Enable the module in the zone configuration with the default signing policy::

   zone:
     - domain: example.com
       module: mod-onlinesign

  Or with an explicit signing policy::

   policy:
     - id: rsa
       algorithm: RSASHA256
       zsk-size: 2048

   mod-onlinesign:
     - id: explicit
       policy: rsa

   zone:
     - domain: example.com
       module: mod-onlinesign/explicit

  Or use manual policy in an analogous manner, see
  :ref:`Manual key management<dnssec-manual-key-management>`.

  .. NOTE::
     Only id, manual, keystore, algorithm, zsk-size, and rrsig-lifetime policy items are
     relevant to this module. If no rrsig-lifetime is configured, the
     default value is 25 hours.

* Make sure the zone is not signed and also that the automatic signing is
  disabled. All is set, you are good to go. Reload (or start) the server:

  .. code-block:: console

   $ knotc reload

The following example stacks the online signing with reverse record synthesis
module::

 mod-synthrecord:
   - id: lan-forward
     type: forward
     prefix: ip-
     ttl: 1200
     network: 192.168.100.0/24

 zone:
   - domain: corp.example.net
     module: [mod-synthrecord/lan-forward, mod-onlinesign]

Module reference
----------------

::

 mod-onlinesign:
   - id: STR
     policy: STR

.. _mod-onlinesign_id:

id
..

A module identifier.

.. _mod-onlinesign_policy:

policy
......

A :ref:`reference<policy_id>` to DNSSEC signing policy. A special *default*
value can be used for the default policy settings.
