.. _mod-synthrecord:

``synthrecord`` – Automatic forward/reverse records
===================================================

This module is able to synthesize either forward or reverse records for
a given prefix and subnet.

Records are synthesized only if the query can't be satisfied from the zone.
Both IPv4 and IPv6 are supported.

.. _mod-synthrecord_example:

Example
-------

Automatic forward records
.........................

::

   mod-synthrecord:
     - id: test1
       type: forward
       prefix: dynamic-
       ttl: 400
       network: 2620:0:b61::/52

   zone:
     - domain: test.
       file: test.zone # Must exist
       module: mod-synthrecord/test1

Result:

.. code-block:: console

   $ kdig AAAA dynamic-2620-0000-0b61-0100-0000-0000-0000-0001.test.
   ...
   ;; QUESTION SECTION:
   ;; dynamic-2620-0000-0b61-0100-0000-0000-0000-0001.test. IN AAAA

   ;; ANSWER SECTION:
   dynamic-2620-0000-0b61-0100-0000-0000-0000-0001.test. 400 IN AAAA 2620:0:b61:100::1

You can also have CNAME aliases to the dynamic records, which are going to be
further resolved:

.. code-block:: console

   $ kdig AAAA alias.test.
   ...
   ;; QUESTION SECTION:
   ;; alias.test. IN AAAA

   ;; ANSWER SECTION:
   alias.test. 3600 IN CNAME dynamic-2620-0000-0b61-0100-0000-0000-0000-0002.test.
   dynamic-2620-0000-0b61-0100-0000-0000-0000-0002.test. 400 IN AAAA 2620:0:b61:100::2

Automatic reverse records
.........................

::

   mod-synthrecord:
     - id: test2
       type: reverse
       prefix: dynamic-
       origin: test
       ttl: 400
       network: 2620:0:b61::/52

   zone:
     - domain: 1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.
       file: 1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.zone # Must exist
       module: mod-synthrecord/test2

Result:

.. code-block:: console

   $ kdig -x 2620:0:b61::1
   ...
   ;; QUESTION SECTION:
   ;; 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa. IN PTR

   ;; ANSWER SECTION:
   1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa. 400 IN PTR
                                  dynamic-2620-0000-0b61-0000-0000-0000-0000-0001.test.

.. _mod-synthrecord_reference:

Module reference
----------------

::

 mod-synthrecord:
   - id: STR
     type: forward | reverse
     prefix: STR
     origin: DNAME
     ttl: INT
     network: ADDR[/INT] | ADDR-ADDR ...

.. _mod-synthrecord_id:

id
..

A module identifier.

.. _mod-synthrecord_type:

type
....

The type of generated records.

Possible values:

- ``forward`` – Forward records
- ``reverse`` – Reverse records

*Required*

.. _mod-synthrecord_prefix:

prefix
......

A record owner prefix.

.. NOTE::
   The value doesn’t allow dots, address parts in the synthetic names are
   separated with a dash.

*Default:* empty

.. _mod-synthrecord_origin:

origin
......

A zone origin (only valid for the :ref:`reverse type<mod-synthrecord_type>`).

*Required*

.. _mod-synthrecord_ttl:

ttl
...

Time to live of the generated records.

*Default:* 3600

.. _mod-synthrecord_network:

network
.......

An IP address, a network subnet, or a network range the query must match.

*Required*
