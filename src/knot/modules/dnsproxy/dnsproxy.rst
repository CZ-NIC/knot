.. _mod-dnsproxy:

``dnsproxy`` – Tiny DNS proxy
=============================

The module forwards all queries, or all specific zone queries if configured
per zone, to the indicated server for resolution. If configured in the fallback
mode, only localy unsatisfied queries are forwarded. I.e. a tiny DNS proxy.
There are several uses of this feature:

* A substitute public-facing server in front of the real one
* Local zones (poor man's "views"), rest is forwarded to the public-facing server
* Using the fallback to forward queries to a resolver
* etc.

.. NOTE::
   The module does not alter the query/response as the resolver would,
   and the original transport protocol is kept as well.

Example
-------

The configuration is straightforward and just a single remote server is
required::

   remote:
     - id: hidden
       address: 10.0.1.1

   mod-dnsproxy:
     - id: default
       remote: hidden
       fallback: on

   template:
     - id: default
       global-module: mod-dnsproxy/default

   zone:
     - domain: local.zone

When clients query for anything in the ``local.zone``, they will be
responded to locally. The rest of the requests will be forwarded to the
specified server (``10.0.1.1`` in this case).

Module reference
----------------

::

 mod-dnsproxy:
   - id: STR
     remote: remote_id
     timeout: INT
     fallback: BOOL
     catch-nxdomain: BOOL

.. _mod-dnsproxy_id:

id
..

A module identifier.

.. _mod-dnsproxy_remote:

remote
......

A :ref:`reference<remote_id>` to a remote server where the queries are
forwarded to.

*Required*

.. _mod-dnsproxy_timeout:

timeout
.......

A remote response timeout in milliseconds.

*Default:* 500

.. _mod-dnsproxy_fallback:

fallback
........

If enabled, localy unsatisfied queries leading to REFUSED (no zone) are forwarded.
If disabled, all queries are directly forwarded without any local attempts
to resolve them.

*Default:* on

.. _mod-dnsproxy_catch-nxdomain:

catch-nxdomain
..............

If enabled, localy unsatisfied queries leading to NXDOMAIN are forwarded.
This option is only relevant in the fallback mode.

*Default:* off
