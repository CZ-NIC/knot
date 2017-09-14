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
   exactly like syslog. See `here
   <https://www.nlnetlabs.nl/bugs-script/show_bug.cgi?id=741#c10>`_ for
   more details.

.. NOTE::
   Dnstap log files can also be created or read using ``kdig``.

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
