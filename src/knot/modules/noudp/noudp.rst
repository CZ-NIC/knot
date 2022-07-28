.. _mod-noudp:

``noudp`` — No UDP response
===========================

The module sends empty truncated reply to a query over UDP. Replies over TCP
are not affected.

Example
-------

To enable this module for all configured zones and every UDP reply::

    template:
      - id: default
        global-module: mod-noudp

Or with specified UDP allow rate::

    mod-noudp:
      - id: sometimes
        udp-allow-rate: 1000  # Don't truncate every 1000th UDP reply

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
   Both *udp-allow-rate* and *udp-truncate-rate* cannot be specified together.

.. _mod-noudp_udp-allow-rate:

udp-allow-rate
..............

Specifies frequency of UDP replies that are not truncated. A non-zero value means
that every N\ :sup:`th` UDP reply is not truncated.

.. NOTE::
   The rate value is associated with one UDP worker. If more UDP workers are
   configured, the specified value may not be obvious to clients.

*Default:* not set

.. _mod-noudp_udp-truncate-rate:

udp-truncate-rate
.................

Specifies frequency of UDP replies that are truncated (opposite of
:ref:`udp-allow-rate <mod-noudp_udp-allow-rate>`). A non-zero value means that
every N\ :sup:`th` UDP reply is truncated.

.. NOTE::
   The rate value is associated with one UDP worker. If more UDP workers are
   configured, the specified value may not be obvious to clients.

*Default:* ``1``
