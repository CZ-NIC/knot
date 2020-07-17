.. _mod-querylog:

``querylog`` — Emit log line for every incomming DNS query
==========================================================

This module helps debugging a DNS server deployment by logging every DNS query.

Example
-------

::

   mod-querylog:
     - id: default
       level: debug

   zone:
     - domain: example.com
       module: mod-querylog/default

Module reference
----------------

::

   mod-querylog:
     - id: STR
       level: critical | error | warning | notice | info | debug

.. _mod-querylog_id:

id
..

A module identifier.

.. _mod-querylog_level:

level
.....

Logging severity level for per-query log messages.
