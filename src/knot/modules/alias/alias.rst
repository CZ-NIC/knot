.. _mod-alias:

``alias`` -- ALIAS record synthesis from locally-served targets
===============================================================

This module synthesises answers to ``A`` and ``AAAA`` queries on nodes
that carry one or more ALIAS records (type 65401), by looking up the
ALIAS target in the server's zone database and copying the target's
address records into the response with the original query name as the
owner.

Only locally-served target zones are followed; external resolution is
out of scope for this module.  The name reflects the current behaviour
and leaves room for future extension (e.g. external resolution).

Behaviour
---------

* Fires only for ``A`` and ``AAAA`` queries.  All other qtypes —
  including ``ALIAS`` itself, ``RRSIG``, ``NSEC`` and ``ANY`` — are
  passed through to the standard resolver, which returns whatever
  records are directly on the node (or NODATA if none of the requested
  type are present).
* ALIAS is additive: if the alias node also has a direct ``A`` or
  ``AAAA`` rrset, both sets are returned merged into one rrset.
* Multiple ALIAS rdata on the same node are followed in turn and their
  results merged.
* ALIASes can not be chained; ALIAS records in the target rrset are
  ignored.
* TTL = ``min(alias_ttl, all contributing source TTLs)``.
* Targets not served by a zone in this server are ignored; external
  resolution is out of scope.
* Synthesised records are not DNSSEC-signed by this module — pair with
  ``mod-onlinesign`` if signed answers are required.
* The module hooks at ``KNOTD_STAGE_PREANSWER``, so for ``A``/``AAAA``
  queries on ALIAS nodes the standard ``solve_answer`` path is
  bypassed.  Other modules hooked at ``KNOTD_STAGE_ANSWER`` will not
  fire for these queries.  Modules at other stages
  (``KNOTD_STAGE_END``, ``KNOTD_STAGE_BEGIN``, etc.) are unaffected —
  e.g. ``mod-stats`` counts ALIAS queries normally.

Use
---

The module has no configuration and is attached at zone scope, typically
via a template so every zone picks it up::

   template:
     - id: default
       module: mod-alias

With the module loaded, a zone carrying an ALIAS record will respond
to ``A``/``AAAA`` queries with the corresponding address records from
a locally-served target zone::

   ; example.com zone:
   www  3600 IN  ALIAS  www._ips.infra.example.net.

   ; infra.example.net zone (served by the same knot):
   www._ips  60 IN  A  203.0.113.10
   www._ips  60 IN  A  203.0.113.11

A query for ``www.example.com. A`` returns ``203.0.113.10`` and
``203.0.113.11``, TTL capped at 60.  A query for any other type on
``www.example.com.`` is handled by the standard resolver and returns
NODATA unless a direct rrset of that type also exists on the node.
