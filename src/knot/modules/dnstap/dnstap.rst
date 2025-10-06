.. _mod-dnstap:

``dnstap`` – Dnstap traffic logging
===================================

A module for query and response logging based on the dnstap_ library.
You can capture either all or zone-specific queries and responses; usually
you want to do the former.

Example
-------

The configuration comprises only a :ref:`mod-dnstap_sink` path parameter,
which can be either a file or a UNIX socket::

   mod-dnstap:
     - id: capture_all
       sink: /tmp/capture.tap

   template:
     - id: default
       global-module: mod-dnstap/capture_all

.. NOTE::
   To be able to use a Unix socket you need an external program to create it.
   Knot DNS connects to it as a client using the libfstrm library. It operates
   exactly like syslog.

.. NOTE::
   Dnstap log files can also be created or read using :doc:`kdig<man_kdig>`.

.. _dnstap: http://dnstap.info/

Module reference
----------------

For all queries logging, use this module in the *default* template. For
zone-specific logging, use this module in the proper zone configuration.

::

 mod-dnstap:
   - id: STR
     sink: STR
     identity: STR
     version: STR
     log-queries: BOOL
     log-responses: BOOL

.. _mod-dnstap_id:

id
..

A module identifier.

.. _mod-dnstap_sink:

sink
....

A sink path, which can be either a file or a UNIX socket when prefixed with
``unix:``.

*Required*

.. WARNING::
   File is overwritten on server startup or reload.

.. _mod-dnstap_identity:

identity
........

A DNS server identity. Set empty value to disable.

*Default:* FQDN hostname

.. _mod-dnstap_version:

version
.......

A DNS server version. Set empty value to disable.

*Default:* server version

.. _mod-dnstap_log-queries:

log-queries
...........

If enabled, query messages will be logged.

*Default:* on

.. _mod-dnstap_log-responses:

log-responses
.............

If enabled, response messages will be logged.

*Default:* on

qps-limit
.........
If set to non-zero, the server will log maximum of qps-limit queries per second and drop other logs.
This is a token bucket approach of how many QPS will be logged every second. Any unused tokens will expire at the end of the second.

*Default:* 0

err-limit
.........
If set to non-zero, the server will log errors upto the err-limit. qps-limit applies to the error logs as well.
But, error queries are allowed to consume additional tokens from future seconds upto err-limit.
If more error queries are logged, that reduces the number of tokens available for regular queries in future without changing logging qps.
In the worst case, if there are too many errors, every second releases qps-limit tokens and only consumed by error queries.

Ex, if qps-limit is 10 and err-limit is 100, after first 10 successful queries are logged, success queries on that second are ignored.
During that second, if failures happen, 90 more failure queries are logged. At the beginning of next second, the available token to normal queries becomes -90 + 10 = -80.
In this case, error has consumed the qps token for next 9 seconds and no success query logs will be added for next 9 seconds.
But, if there were errors during those seconds, it still has 10 tokens per second to consume on error side. So upto 10 errors can be logged during those seconds.
If nothing is logged for next 9 seconds, at the end of 9 seconds, the system resets to default limit of regular queries with 10 tokens, and errors with 100 tokens.
In the long run, errors and success can consume only qps-limit. But errors are prioritized and allowed to consume more tokens at the expense of success.

*Default:* 0

query-with-resp
...............
If set to on, logs query packet along with response packet to reduce round trip and also to make analysis easier.

*Default:* off