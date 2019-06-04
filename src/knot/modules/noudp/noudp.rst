.. _mod-noudp:

``noudp`` — No UDP response
===========================

The module sends empty truncated response to any UDP query. TCP queries are
not affected.

Example
-------

To enable this module globally, you need to add something like the following
to the configuration file::

    mod-noudp:
      - id: default
        udp-allow-rate: 1000
        
    template:
      - id: default
        global-module: mod-noudp/default

Module reference
----------------

::

  mod-noudp:
   - id: STR
     udp-allow-rate: INT

.. _mod-noudp_udp-allow-rate:

udp-allow-rate
..............

Value of `udp-allow-rate` specify how much UDP queries will pass the filter. Value 0 
for none UDP query will pass the filter, non-zero value means every N-th UDP query
will pass the filter.

*Default:* 0

.. NOTE::
   Rate of allowed UDP queries is associated with UDP worker (rate counter per worker).
