.. _mod-noudp:

``noudp`` — No UDP response
===========================

The module sends empty truncated response to a UDP query. TCP queries are
not affected.

Example
-------

To enable this module for all configured zones and every UDP query::

    template:
      - id: default
        global-module: mod-noudp

Or with specified UDP allow rate::

    mod-noudp:
      - id: sometimes
        udp-allow-rate: 1000  # Don't truncate every 1000th UDP query

    template:
      - id: default
        module: mod-noudp/sometimes

Module reference
----------------

::

  mod-noudp:
   - id: STR
     udp-allow-rate: INT
     udp-truncate-rate: INT

.. NOTE::
   Both *udp-allow-rate* and *udp-truncate-rate* cannot be specified at
   the same time. 

.. _mod-noudp_udp-allow-rate:

udp-allow-rate
..............

Specifies how many UDP queries pass through the filter. A value 0 means that
none will pass. A non-zero value means that every N\ :sup:`th` UDP query passes
the filter.

.. NOTE::
   The rate value is associated with one UDP worker. If more UDP workers are
   configured, the specified value may not be obvious to clients.

*Default:* 0

.. _mod-noudp_udp-truncate-rate:

udp-truncate-rate
.................

Specifies how many UDP queries pass throuh the filter. A value 0 means that
every query passes. A non-zero value means that every N\ :sup:`th` UDP query
does not pass the filter.

.. NOTE::
   The rate value is associated with one UDP worker. If more UDP workers are
   configured, the specified value may not be obvious to clients.

*Default:* 1
