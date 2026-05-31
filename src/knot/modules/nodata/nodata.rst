.. _mod-nodata:

``nodata`` — NODATA synthesis
=============================

The module synthesizes authoritative negative responses for queries
targeting zones that are not configured on the server. Instead of
returning ``REFUSED``, the server responds with a NODATA-style answer
containing a synthetic SOA record:

- For non-SOA queries, the authority section contains a synthetic SOA record
  with an owner name matching the queried name and the answer
- For SOA queries, the synthetic SOA record is placed in the answer
  section and the authority section is empty.

This can reduce unnecessary query traffic from recursive resolvers and
clients repeatedly retrying queries for non-existent zones delegated to
the server.

.. NOTE::
   This module introduces two statistics counters:

   - ``answer`` – The number of queries answered with SOA in the answer section.
   - ``authority`` – The number of queries answered with SOA in the authority section.

Example
-------

Module loaded with the default configuration::

  template:
    - id: default
      global-module: mod-nodata

Module reference
----------------

::

  mod-nodata:
   - id: STR
     ttl: TIME

.. _mod-nodata_id:

id
..

A module identifier.

.. _mod-nodata_ttl:

ttl
...

TTL of the synthetic SOA record returned by the module. The same value
is also used for all SOA timer fields.

*Default:* ``30``
