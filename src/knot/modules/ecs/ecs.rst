.. _mod-ecs:

``ecs`` — EDNS Client Subnet scope
==================================

With :ref:`server_edns-client-subnet` enabled, the server echoes the EDNS
Client Subnet option from the query back with a zero SCOPE PREFIX-LENGTH,
which declares the response valid for all addresses (:rfc:`7871`). This
module sets the SCOPE PREFIX-LENGTH to the SOURCE PREFIX-LENGTH of the
query instead, declaring that the response applies to exactly the disclosed
client subnet.

It is intended for setups where the zone contents are actually selected per
client subnet outside of the server, e.g. by a load balancer picking
between several presigned zone variants. Enabling this module on a zone
whose answers don't depend on the client subnet only makes them needlessly
harder to cache.

A zero source prefix length results in a zero scope prefix length, as
required by :rfc:`7871`.

Example
-------

::

    server:
        edns-client-subnet: on

    zone:
      - domain: example.com
        module: mod-ecs

.. NOTE::
   This module is not configurable.
