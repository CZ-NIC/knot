.. _mod-queryacl:

``queryacl`` — Limit queries by remote address or target interface
==================================================================

This module provides a simple way to whitelist incoming queries
according to the query's source address or target interface.
It can be used e.g. to create a restricted-access subzone with delegations from the corresponding public zone.
The module may be enabled both globally and per-zone.

.. NOTE::
    The module limits only regular queries. Notify, transfer and update are handled by :ref:`ACL<ACL>`.

Example
-------

::

   mod-queryacl:
     - id: default
       address: [192.0.2.73-192.0.2.90, 203.0.113.0/24]
       interface: 198.51.100

   zone:
     - domain: example.com
       module: mod-queryacl/default

Module reference
----------------

::

   mod-queryacl:
     - id: STR
       address: ADDR[/INT] | ADDR-ADDR ...
       interface: ADDR[/INT] | ADDR-ADDR ...

.. _mod-queryacl_id:

id
..

A module identifier.

.. _mod-queryacl_address:

address
.......

A list of allowed ranges and/or subnets for query's source address. If the query's address does not fall into any
of the configured ranges, NOTAUTH rcode is returned.

.. _mod-queryacl_interface:

interface
.........

A list of allowed ranges and/or subnets for query's target interface. If the interface does not fall into any
of the configured ranges, NOTAUTH rcode is returned. Note that every interface used has to be configured in :ref:`listen<server_listen>`.

