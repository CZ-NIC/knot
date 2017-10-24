.. _mod-stats:

``stats`` — Query statistics
============================

The module extends server statistics with incoming DNS request and corresponding
response counters, such as used network protocol, total number of responded bytes,
etc (see module reference for full list of supported counters).
This module should be configured as the last module.

.. NOTE::
   Server initiated communication (outgoing NOTIFY, incoming \*XFR,...) is not
   counted by this module.

.. NOTE::
   Leading 16-bit message size over TCP is not considered.

Example
-------

Common statistics with default module configuration::

    template:
      - id: default
        global-module: mod-stats

Per zone statistics with explicit module configuration::

    mod-stats:
      - id: custom
        edns-presence: on
        query-type: on

    template:
      - id: default
        module: mod-stats/custom

Module reference
----------------

::

 mod-stats:
   - id: STR
     request-protocol: BOOL
     server-operation: BOOL
     request-bytes: BOOL
     response-bytes: BOOL
     edns-presence: BOOL
     flag-presence: BOOL
     response-code: BOOL
     reply-nodata: BOOL
     query-type: BOOL
     query-size: BOOL
     reply-size: BOOL

.. _mod-stats_id:

id
..

A module identifier.

.. _mod-stats_request-protocol:

request-protocol
................

If enabled, all incoming requests are counted by the network protocol:

* udp4 - UDP over IPv4
* tcp4 - TCP over IPv4
* udp6 - UDP over IPv6
* tcp6 - TCP over IPv6

*Default:* on

.. _mod-stats_server-operation:

server-operation
................

If enabled, all incoming requests are counted by the server operation. The
server operation is based on message header OpCode and message query (meta) type:

* query - Normal query operation
* update - Dynamic update operation
* notify - NOTIFY request operation
* axfr - Full zone transfer operation
* ixfr - Incremental zone transfer operation
* invalid - Invalid server operation

*Default:* on

.. _mod-stats_request-bytes:

request-bytes
.............

If enabled, all incoming request bytes are counted by the server operation:

* query - Normal query bytes
* update - Dynamic update bytes
* other - Other request bytes

*Default:* on

.. _mod-stats_response-bytes:

response-bytes
..............

If enabled, outgoing response bytes are counted by the server operation:

* reply - Normal response bytes
* transfer - Zone transfer bytes
* other - Other response bytes

.. WARNING::
   Dynamic update response bytes are not counted by this module.

*Default:* on

.. _mod-stats_edns-presence:

edns-presence
.............

If enabled, EDNS pseudo section presence is counted by the message direction:

* request - EDNS present in request
* response - EDNS present in response

*Default:* off

.. _mod-stats_flag-presence:

flag-presence
.............

If enabled, some message header flags are counted:

* TC - Truncated Answer in response
* DO - DNSSEC OK in request

*Default:* off

.. _mod-stats_response-code:

response-code
.............

If enabled, outgoing response code is counted:

* NOERROR
* ...
* NOTZONE
* BADVERS
* ...
* BADCOOKIE
* other - All other codes

.. NOTE::
   In the case of multi-message zone transfer response, just one counter is
   incremented.

.. WARNING::
   Dynamic update response code is not counted by this module.

*Default:* on

.. _mod-stats_reply-nodata:

reply-nodata
............

If enabled, NODATA pseudo RCODE (:rfc:`2308#section-2.2`) is counted by the
query type:

* A
* AAAA
* other - All other types

*Default:* off

.. _mod-stats_query-type:

query-type
..........

If enabled, normal query type is counted:

* A (TYPE1)
* ...
* TYPE65
* SPF (TYPE99)
* ...
* TYPE110
* ANY (TYPE255)
* ...
* TYPE260
* other - All other types

.. NOTE::
   Not all assigned meta types (IXFR, AXFR,...) have their own counters,
   because such types are not processed as normal query.

*Default:* off

.. _mod-stats_query-size:

query-size
..........

If enabled, normal query message size distribution is counted by the size range
in bytes:

* 0-15
* 16-31
* ...
* 272-287
* 288-65535

*Default:* off

.. _mod-stats_reply-size:

reply-size
..........

If enabled, normal reply message size distribution is counted by the size range
in bytes:

* 0-15
* 16-31
* ...
* 4080-4095
* 4096-65535

*Default:* off
