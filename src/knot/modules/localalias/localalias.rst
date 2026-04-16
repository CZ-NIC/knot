.. _mod-localalias:

``localalias`` -- ALIAS record synthesis from locally-served targets
====================================================================

This module synthesises answers for ALIAS records (type 65401) at query
time by looking up the ALIAS target in the server's zone database and
copying the target's records into the response with the original query
name as the owner.

Behaviour
---------

* Fires for any qtype except ``ALIAS`` itself, ``RRSIG``, and ``NSEC``.
* ALIAS is additive: if the alias node also has a direct rrset of the
  queried type, both sets are returned merged into one rrset.
* Multiple ALIAS rdata on the same node are followed in turn and their
  results merged.
* ALIASes can not be chained, ALIAS records in the target rrset will be
  ignored.
* For qtype ``ANY`` the module synthesises a single rrset (RFC 8482) —
  the first non-skipped type found on the first locally-served target —
  so the raw ALIAS record is not exposed to clients.
* TTL = ``min(alias_ttl, all contributing source TTLs)``.
* Targets not served by a zone in this server are ignored; external
  resolution is out of scope.
* Synthesised records are not DNSSEC-signed.
* The module hooks at ``KNOTD_STAGE_PREANSWER``, so for ALIAS nodes the
  standard ``solve_answer`` path is bypassed.  Other modules hooked at
  ``KNOTD_STAGE_ANSWER`` will not fire for these nodes.  Modules at
  other stages (``KNOTD_STAGE_END``, ``KNOTD_STAGE_BEGIN``, etc.) are
  unaffected — e.g. ``mod-stats`` counts ALIAS queries normally.

Use
---

The module has no configuration and is attached at zone scope, typically
via a template so every zone picks it up::

   template:
     - id: default
       module: mod-localalias

With the module loaded, a zone carrying an ALIAS record will respond
to queries for its address types from a locally-served target zone::

   ; example.com zone:
   www  3600 IN  ALIAS  www._ips.infra.example.net.

   ; infra.example.net zone (served by the same knot):
   www._ips  60 IN  A  203.0.113.10
   www._ips  60 IN  A  203.0.113.11

A query for ``www.example.com. A`` returns ``203.0.113.10`` and
``203.0.113.11``, TTL capped at 60.
