.. _mod-rosedb:

``rosedb`` – Static resource records
====================================

The module provides a mean to override responses for certain queries before
the record is searched in the available zones. The module comes with the
``rosedb_tool`` tool used to manipulate the database of static records.

For example, let's suppose we have a database of following records:

.. code-block:: none

   myrecord.com.      3600 IN A 127.0.0.1
   www.myrecord.com.  3600 IN A 127.0.0.2
   ipv6.myrecord.com. 3600 IN AAAA ::1

And we query the nameserver with the following:

.. code-block:: console

   $ kdig IN A myrecord.com
     ... returns NOERROR, 127.0.0.1
   $ kdig IN A www.myrecord.com
     ... returns NOERROR, 127.0.0.2
   $ kdig IN A stuff.myrecord.com
     ... returns NOERROR, 127.0.0.1
   $ kdig IN AAAA myrecord.com
     ... returns NOERROR, NODATA
   $ kdig IN AAAA ipv6.myrecord.com
     ... returns NOERROR, ::1

An entry in the database matches anything at the same or a lower domain
level, i.e. 'myrecord.com' matches 'a.a.myrecord.com' as well.
This can be utilized to create catch-all entries.

You can also add authority information for the entries, provided you create
SOA + NS records for a name, like so:

.. code-block:: none

   myrecord.com.     3600 IN SOA master host 1 3600 60 3600 3600
   myrecord.com.     3600 IN NS ns1.myrecord.com.
   myrecord.com.     3600 IN NS ns2.myrecord.com.
   ns1.myrecord.com. 3600 IN A 127.0.0.1
   ns2.myrecord.com. 3600 IN A 127.0.0.2

In this case, the responses will:

1. Be authoritative (AA flag set)
2. Provide an authority section (SOA + NS)
3. Be NXDOMAIN if the name is found *(i.e. the 'IN AAAA myrecord.com' from
   the example)*, but not the RR type *(this is to allow the synthesis of
   negative responses)*

The SOA record applies only to the 'myrecord.com.', not to any other
record (not even those of its subdomains). From this point of view, all records
in the database are unrelated and not hierarchical. The idea is to provide
subtree isolation for each entry.

In addition, the module is able to log matching queries via remote syslog if
you specify a syslog address endpoint and an optional string code.

Example
-------

* Create the entries in the database:

  .. code-block:: console

   $ mkdir /tmp/static_rrdb
   $ # No logging
   $ rosedb_tool /tmp/static_rrdb add myrecord.com. A 3600 "127.0.0.1" "-" "-"
   $ # Logging as 'www_query' to Syslog at 10.0.0.1
   $ rosedb_tool /tmp/static_rrdb add www.myrecord.com. A 3600 "127.0.0.1" \
                                                    "www_query" "10.0.0.1"
   $ # Logging as 'ipv6_query' to Syslog at 10.0.0.1
   $ rosedb_tool /tmp/static_rrdb add ipv6.myrecord.com. AAAA 3600 "::1" \
                                                 "ipv6_query" "10.0.0.1"
   $ # Verify settings
   $ rosedb_tool /tmp/static_rrdb list
   www.myrecord.com.       A RDATA=10B     www_query       10.0.0.1
   ipv6.myrecord.com.      AAAA RDATA=22B  ipv6_query      10.0.0.1
   myrecord.com.           A RDATA=10B     -               -

.. NOTE::
   The database may be modified later on while the server is running.

* Configure the query module::

   mod-rosedb:
     - id: default
       dbdir: /tmp/static_rrdb

   template:
     - id: default
       global-module: mod-rosedb/default

The module accepts just one parameter – the path to the directory where
the database will be stored.

* Start the server:

  .. code-block:: console

   $ knotd -c knot.conf

* Verify the running instance:

  .. code-block:: console

   $ kdig @127.0.0.1#6667 A myrecord.com

Module reference
----------------

::

 mod-rosedb:
   - id: STR
     dbdir: STR

.. _mod-rosedb_id:

id
..

A module identifier.

.. _mod-rosedb_dbdir:

dbdir
.....

A path to the directory where the database is stored.

*Required*
