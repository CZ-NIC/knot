.. meta::
   :description: reStructuredText plaintext markup language

.. _Configuration:

*************
Configuration
*************

Simple configuration
====================

The following configuration presents a simple configuration file
which can be used as a base for your Knot DNS setup::

    # Example of a very simple Knot DNS configuration.

    server:
        listen: 0.0.0.0@53
        listen: ::@53

    zone:
      - domain: example.com
        storage: /var/lib/knot/zones/
        file: example.com.zone

    log:
      - to: syslog
        any: info

Now let's go step by step through this configuration:

- The :ref:`server_listen` statement in the :ref:`server section<Server section>`
  defines where the server will listen for incoming connections.
  We have defined the server to listen on all available IPv4 and IPv6 addresses
  all on port 53.
- The :ref:`zone section<Zone section>` defines the zones that the server will
  serve. In this case we defined one zone named *example.com* which is stored
  in the zone file */var/lib/knot/zones/example.com.zone*.
- The :ref:`log section<Logging section>` defines the log facilities for
  the server. In this example we told Knot DNS to send its log messages with
  the severity ``info`` or more serious to the syslog.

For detailed description of all configuration items see
:ref:`Configuration Reference`.

Zone templates
==============

A zone template allows single zone configuration to be shared among more zones.
Each template option can be explicitly overridden in the zone configuration.
A ``default`` template identifier is reserved for the default template::

    template:
      - id: default
        storage: /var/lib/knot/master
        semantic-checks: on

      - id: signed
        storage: /var/lib/knot/signed
        dnssec-enable: on
        semantic-checks: on

      - id: slave
        storage: /var/lib/knot/slave

    zone:
      - domain: example1.com     # Uses default template

      - domain: example2.com     # Uses default template
        semantic-checks: off     # Override default settings

      - domain: example.cz
        template: signed

      - domain: example1.eu
        template: slave
        master: master1

      - domain: example2.eu
        template: slave
        master: master2

Access control list (ACL)
=========================

ACL list specifies which remotes are allowed to send the server a specific
query or do a specific action. A remote can be a single IP address or a
network subnet. Also a TSIG key can be specified::

    acl:
      - id: single_rule
        address: 192.168.1.1      # Single IP address
        action: [notify, update]  # Allow zone notifications and updates zone

      - id: subnet_rule
        address: 192.168.2.0/24   # Network subnet
        action: xfer              # Allow zone transfers

      - id: deny_rule
        address: 192.168.2.100    # Negative match
        action: deny              # The remote query is denied

      - id: key_rule
        key: key1                 # Access based just on TSIG key
        action: xfer

Then the rules are referenced from zone :ref:`template_acl` or from
control :ref:`control_acl`::

    zone:
      - domain: example.com
        acl: [single_rule, deny_rule, subnet_rule, key_rule]

Slave zone
==========

Knot DNS doesn't strictly differ between master and slave zones. The
only requirement is to have :ref:`master<template_master>` statement set for
the given zone. Also note that you need to explicitly allow incoming zone
changed notifications via ``notify`` :ref:`acl_action` through zone's
:ref:`template_acl` list, otherwise the server reject them. If the zone
file doesn't exist it will be bootstrapped over AXFR::

    remote:
      - id: master
        address: 192.168.1.1@53

    acl:
      - id: master_acl
        address: 192.168.1.1
        action: notify

    zone:
      - domain: example.com
        storage: /var/lib/knot/zones/
        # file: example.com.zone   # Default value
        master: master
        acl: master_acl

Note that the :ref:`template_master` option accepts a list of multiple remotes.
The first remote in the list is used as the primary master, and the rest is used
for failover if the connection with the primary master fails.
The list is rotated in this case, and a new primary is elected.
The preference list is reset on the configuration reload.

You can also use TSIG for authenticated communication. For this, you need
to configure a key and assign it to the remote and to the proper ACL rule::

    key:
      - id: slave1_key
        algorithm: hmac-md5
        secret: Wg==

    remote:
      - id: master
        address: 192.168.1.1@53
        key: slave1_key

    acl:
      - id: master_acl
        address: 192.168.1.1
        key: slave1_key
        action: notify

Master zone
===========

Master zone often needs to specify who is allowed to transfer the zone. This
is done by defining ACL rules with ``xfer`` action. An ACL rule can consists
of single address or network subnet or/with a TSIG key::

    remote:
      - id: slave1
        address: 192.168.2.1@53

    acl:
      - id: slave1_acl
        address: 192.168.2.1
        action: xfer

      - id: others_acl
        address: 192.168.3.0/24
        action: xfer

    zone:
      - domain: example.com
        storage: /var/lib/knot/zones/
        file: example.com.zone
        notify: slave1
        acl: [slave1_acl, others_acl]

And TSIG application::

    key:
      - id: slave1_key
        algorithm: hmac-md5
        secret: Wg==

    remote:
      - id: slave1
        address: 192.168.2.1@53
        key: slave1_key

    acl:
      - id: slave1_acl
        address: 192.168.2.1
        key: slave1_key
        action: xfer

      - id: others_acl
        address: 192.168.3.0/24
        action: xfer

Dynamic updates
===============

Dynamic updates for the zone is allowed via proper ACL rule with ``update``
action. If the zone is configured as a slave and DNS update messages is
accepted, server forwards the message to its primary master. When it
receives the response from primary master, it forwards it back to the
originator. This finishes the transaction.

However, if the zone is configured as master, it accepts such an UPDATE and
processes it::

    acl:
      - id: update_acl
        address: 192.168.3.0/24
        action: update

    zone:
      - domain: example.com
        file: example.com.zone
        acl: update_acl

Response rate limiting
======================

Response rate limiting (RRL) is a method to combat recent DNS
reflection amplification attacks. These attacks rely on the fact
that source address of a UDP query could be forged, and without a
worldwide deployment of BCP38, such a forgery could not be detected.
Attacker could then exploit DNS server responding to every query,
potentially flooding the victim with a large unsolicited DNS
responses.

You can enable RRL with the :ref:`server_rate-limit` option in the
:ref:`server section<Server section>`. Setting to a value greater than ``0``
means that every flow is allowed N responses per second, (i.e. ``rate-limit
50;`` means ``50`` responses per second). It is also possible to
configure :ref:`server_rate-limit-slip` interval, which causes every Nth
``blocked`` response to be slipped as a truncated response::

    server:
        rate-limit: 200     # Each flow is allowed to 200 resp. per second
        rate-limit-slip: 1  # Every response is slipped

Automatic DNSSEC signing
========================

Example configuration
---------------------

The example configuration enables automatic signing for all zones
using :ref:`template_dnssec-enable` option in the default template, but the
signing is explicitly disabled for zone ``example.dev`` using the same
option directly in zone configuration. The location of directory with
signing keys is set globally by option :ref:`template_dnssec-keydir`::

    template:
      - id: default
        dnssec-enable: on
        dnssec-keydir: /var/lib/knot/keys

    zone:
      - domain: example.com
        file: example.com.zone

      - domain: example.dev
        file: example.dev.zone
        dnssec-enable: off

Signing keys
------------

The signing keys can be generated using ISC ``dnssec-keygen`` tool
only and there are some limitations:

* Keys for all zones must be placed in one directory.
* Only key publication, activation, inactivation, and removal time
  stamps are utilized. Other time stamps are ignored.
* It is required, that both ``.private`` and ``.key`` files for each
  key are available in the key directory in order to use the keys
  (even for verification only).
* There cannot be more than eight keys per zone. Keys which are not
  published are not included in this number.

Example how to generate NSEC3 capable zone signing key (ZSK) and key
signing key (KSK) for zone ``example.com``::

    $ cd /var/lib/knot/keys
    $ dnssec-keygen -3 example.com
    $ dnssec-keygen -3 -f KSK example.com

Signing policy
--------------

Currently the signing policy is not configurable, except for signature
lifetime.

* Signature lifetime can be set in configuration globally for all
  zones and for each zone in particular. :ref:`template_signature-lifetime`.
  If not set, the default value is 30 days.
* Signature is refreshed 2 hours before expiration. The signature
  lifetime must thus be set to more than 2 hours.

Zone signing
------------

The signing process consists of the following steps:

* Fixing ``NSEC`` or ``NSEC3`` records. This is determined by
  ``NSEC3PARAM`` record presence in unsigned zone.
* Updating ``DNSKEY`` records. This also means adding DNSKEY records
  for any keys that are present in keydir, but missing in zone file.
* Removing expired signatures, invalid signatures, signatures expiring
  in a short time, and signatures with unknown key.
* Creating missing signatures. Unless the Single-Type Signing Scheme
  is used, ``DNSKEY`` records in a zone apex are signed by KSK keys and
  all other records are signed by ZSK keys.
* SOA record is updated and resigned if any changes were performed.

The zone signing is performed when the zone is loaded into server, on
zone reload, before any signature is expiring, and after DDNS
update. The signing can be also forced using ``signzone`` command
issued by ``knotc``, in this case all signatures are recreated. After
each zone signing, a new signing event is planned. User can view the
time of this event by using the ``knotc zonestatus`` command.

Query modules
=============

Knot DNS supports configurable query modules that can alter the way
queries are processed. The concept is quite simple - each query
requires a finite number of steps to be resolved. We call this set of
steps a query plan, an abstraction that groups these steps into
several stages.

* Before query processing
* Answer, Authority, Additional records packet sections processing
* After query processing

For example, processing an Internet zone query needs to find an
answer. Then based on the previous state, it may also append an
authority SOA or provide additional records. Each of these actions
represents a 'processing step'. Now if a query module is loaded for a
zone, it is provided with an implicit query plan, and it is allowed to
extend it or even change it altogether.

Each module is configured in the corresponding module section and is
identified for the subsequent usage. Then, the identifier is referenced
through :ref:`template_module` option (in the form of ``module_name/module_id``)
in the zone section or in the ``default`` template if it used for all queries.

``dnstap`` - dnstap-enabled query logging
-----------------------------------------

Module for query and response logging based on dnstap_ library.
You can capture either all or zone-specific queries and responses, usually
you want to do the former. The configuration consists only from a
:ref:`mod-dnstap_sink` path parameter, which can either be a file or
a UNIX socket::

    mod-dnstap:
      - id: capture_all
        sink: /tmp/capture.tap

    template:
      - id: default
        module: mod-dnstap/capture_all

.. _dnstap: http://dnstap.info/

``synth_record`` - Automatic forward/reverse records
----------------------------------------------------

This module is able to synthetise either forward or reverse records for
given prefix and subnet.

Records are synthetised only if the query can't be satisfied from the zone.
Both IPv4 and IPv6 are supported.

*Note: long names are snipped for readability.*

Automatic forward records
-------------------------

Example::

   mod-synth-record:
     - id: test1
       type: forward
       prefix: dynamic-
       ttl: 400
       address: 2620:0:b61::/52

   zone:
     - domain: example.
       file: example.zone # Zone file have to exist!
       module: mod-synth-record/test1

Result::

   $ kdig AAAA dynamic-2620-0000-0b61-0100-0000-0000-0000-0000.example.
   ...
   ;; QUESTION SECTION:
   ;; dynamic-2620-0000-0b61-0100-0000-0000-0000-0000.example. 0	IN	AAAA

   ;; ANSWER SECTION:
   dynamic-2620-0000-0b61-0100... 400 IN AAAA 2620:0:b61:100::

You can also have CNAME aliases to the dynamic records, which are going to be
further resoluted::

   $ kdig AAAA hostalias.example.
   ...
   ;; QUESTION SECTION:
   ;hostalias.example. 0	IN	AAAA

   ;; ANSWER SECTION:
   hostalias.example. 3600 IN CNAME dynamic-2620-0000-0b61-0100...
   dynamic-2620-0000-0b61-0100... 400  IN AAAA  2620:0:b61:100::

Automatic reverse records
-------------------------

Example::

   mod-synth-record:
     - id: test2
       type: reverse
       prefix: dynamic-
       zone: example
       ttl: 400
       address: 2620:0:b61::/52

   zone:
     - domain: 1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.
       file: 1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.zone # Zone file have to exist!
       module: mod-synth-record/test2

Result::

   $ kdig PTR 1.0.0...1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.
   ...
   ;; QUESTION SECTION:
   ;; 1.0.0...1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa. 0	IN	PTR

   ;; ANSWER SECTION:
   ... 400 IN PTR dynamic-2620-0000-0b61-0000-0000-0000-0000-0001.example.

Limitations
^^^^^^^^^^^

* As of now, there is no authenticated denial of nonexistence (neither
  NSEC or NSEC3 is supported) nor DNSSEC signed records.  However,
  since the module is hooked in the query processing plan, it will be
  possible to do online signing in the future.

``dnsproxy`` - Tiny DNS proxy
-----------------------------

The module catches all unsatisfied queries and forwards them to the
configured server for resolution, i.e. a tiny DNS proxy. This can be useful
for several things:

* A substitute public-facing server in front of the real one
* Local zones (poor man's "views"), rest is forwarded to the public-facing server
* etc.

*Note: The module does not alter the query/response as the resolver would do,
also the original transport protocol is kept.*

The configuration is straightforward and just accepts a single IP address
(either IPv4 or IPv6)::

   mod-dnsproxy:
     - id: default
       remote: 10.0.1.1

   template:
     - id: default
       module: mod-dnsproxy/default

   zone:
     - domain: local.zone

Now when the clients query for anything in the ``local.zone``, it will be
answered locally. Rest of the requests will be forwarded to the specified
server (``10.0.1.1`` in this case).

``rosedb`` - Static resource records
------------------------------------

The module provides a mean to override responses for certain queries before
the record is searched in the available zones. The modules comes with a tool
``rosedb_tool`` to manipulate with the database of static records.
Neither the tool nor the module are enabled by default, recompile with
the configure flag ``--enable-rosedb`` to enable them.

For example, suppose we have a database of following records::

   myrecord.com.      3600 IN A 127.0.0.1
   www.myrecord.com.  3600 IN A 127.0.0.2
   ipv6.myrecord.com. 3600 IN AAAA ::1

And we query the nameserver with following::

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

*Note: An entry in the database matches anything at or below it,
i.e. 'myrecord.com' matches 'a.a.myrecord.com' as well.
This can be exploited to create a catch-all entries.*

You can also add an authority information for the entries, provided you create
a SOA + NS records for a name, like so::

   myrecord.com.     3600 IN SOA master host 1 3600 60 3600 3600
   myrecord.com.     3600 IN NS ns1.myrecord.com.
   myrecord.com.     3600 IN NS ns2.myrecord.com.
   ns1.myrecord.com. 3600 IN A 127.0.0.1
   ns2.myrecord.com. 3600 IN A 127.0.0.2

In this case, the responses will:

1. Be authoritative (AA flag set)
2. Provide an authority section (SOA + NS)
3. NXDOMAIN if the name is found *(i.e. the 'IN AAAA myrecord.com' from
   the example)*, but not the RR type *(this is to allow synthesis of negative
   responses)*

*Note: The SOA record applies only to the 'myrecord.com.', not to any other
record (even below it). From this point of view, all records in the database
are unrelated and not hierarchical. The reasoning is to provide a subtree
isolation for each entry.*

In addition the module is able to log matching queries via remote syslog if
you specify a syslog address endpoint and an optional string code.

Here is an example on how to use the module:

* Create the entries in the database::

   $ mkdir /tmp/static_rrdb
   $ rosedb_tool /tmp/static_rrdb add myrecord.com. A 3600 "127.0.0.1" "-" "-" # No logging
   $ rosedb_tool /tmp/static_rrdb add www.myrecord.com. A 3600 "127.0.0.1" "www_query" "10.0.0.1" # Syslog @ 10.0.0.1
   $ rosedb_tool /tmp/static_rrdb add ipv6.myrecord.com. AAAA 3600 "::1" "ipv6_query" "10.0.0.1" # Syslog @ 10.0.0.1
   $ rosedb_tool /tmp/static_rrdb list # Verify
   www.myrecord.com.       A RDATA=10B     www_query       10.0.0.1
   ipv6.myrecord.com.      AAAA RDATA=22B  ipv6_query      10.0.0.1
   myrecord.com.           A RDATA=10B     -               -

 *Note: the database may be modified while the server is running later on.*

* Configure the query module::

   mod-rosedb:
     - id: default
       dbdir: /tmp/static_rrdb

   template:
     - id: default
       module: mod-rosedb/default

  *Note: The module accepts just one parameter - path to the directory where
  the database will be stored.*

* Start the server::

   $ knotd -c knot.conf

* Verify the running instance::

   $ kdig @127.0.0.1#6667 A myrecord.com
