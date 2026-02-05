.. _mod-append:

``append`` — supplement response
================================

Enhance DNS responses by attaching pre-defined addresses to any queries that
match the specified ``labels`` prefixes.

Example
-------

Activate the appending functionality for a specific zone using the following configuration

::

    mod-append:
      - id: custom
        zone: example.net.
        a: 127.0.0.1
        aaaa: ::1
        labels: [ a ]

    zone:
      - id: example.com
        module: mod-append/custom

With this setup, a query for `a.example.com. A`` will trigger an additional
record in the response for `a.example.net A 127.0.0.1`. The same logic
applies to IPv6 queries.

Module reference
----------------

::

    mod-append:
      - id: STR
        zone: DNAME
        a: IP
        aaaa: IPv6
        labels: DNAME ...
        ttl: INT

.. _mod-append_id:

id
..

A module identifier.

.. _mod-append_zone:

zone
....

Defines the replacement domain suffix that will be used in the appended record
instead of the original zone suffix.

*Required*

.. _mod-append_a:

a
.

The IPv4 address to be inserted into the response for A-type queries.

*Default:* not set

.. _mod-append_aaaa:

aaaa
....

The IPv6 address to be inserted into the response for AAAA-type queries.

*Default:* not set

.. _mod-append_labels:

labels
......

A list of permitted domain name prefixes that act as a filter; the module
only appends records when the query matches a prefix in this list.

*Required*

.. _mod-append_ttl:

ttl
...

TTL value of attached record.

*Default:* 86400
