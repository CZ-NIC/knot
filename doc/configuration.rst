.. highlight:: yaml
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
      - target: syslog
        any: info

Now let's go step by step through this configuration:

- The :ref:`server_listen` statement in the :ref:`server section<Server section>`
  defines where the server will listen for incoming connections.
  We have defined the server to listen on all available IPv4 and IPv6 addresses
  all on port 53.
- The :ref:`zone section<Zone section>` defines the zones that the server will
  serve. In this case we defined one zone named *example.com* which is stored
  in the zone file :file:`/var/lib/knot/zones/example.com.zone`.
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
        dnssec-signing: on
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
request. A remote can be a single IP address or a network subnet. Also a TSIG
key can be specified::

    acl:
      - id: address_rule
        address: [2001:db8::1, 192.168.2.0/24] # Allowed IP address list
        action: [transfer, update]  # Allow zone transfers and updates

      - id: deny_rule             # Negative match rule
        address: 192.168.2.100
        action: transfer
        deny: on                  # The request is denied

      - id: key_rule
        key: key1                 # Access based just on TSIG key
        action: transfer

These rules can then be referenced from a zone :ref:`zone_acl`::

    zone:
      - domain: example.com
        acl: [address_rule, deny_rule, key_rule]

Slave zone
==========

Knot DNS doesn't strictly differ between master and slave zones. The
only requirement is to have :ref:`master<zone_master>` statement set for
the given zone. Also note that you need to explicitly allow incoming zone
changed notifications via ``notify`` :ref:`acl_action` through zone's
:ref:`zone_acl` list, otherwise the update will be rejected by the server.
If the zone file doesn't exist it will be bootstrapped over AXFR::

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

Note that the :ref:`zone_master` option accepts a list of multiple remotes.
The first remote in the list is used as the primary master, and the rest is used
for failover if the connection with the primary master fails.
The list is rotated in this case, and a new primary is elected.
The preference list is reset on the configuration reload.

To use TSIG for transfer authentication, configure a TSIG key and assign the
key to the remote. If the notifications are used, the same key should be
configured in a proper ACL rule::

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

An ACL with the ``transfer`` action must be configured to allow outgoing zone
transfers. An ACL rule consists of a single address or a network subnet::

    remote:
      - id: slave1
        address: 192.168.2.1@53

    acl:
      - id: slave1_acl
        address: 192.168.2.1
        action: transfer

      - id: others_acl
        address: 192.168.3.0/24
        action: transfer

    zone:
      - domain: example.com
        storage: /var/lib/knot/zones/
        file: example.com.zone
        notify: slave1
        acl: [slave1_acl, others_acl]

Optionally a TSIG key can be specified::

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
        action: transfer

      - id: others_acl
        address: 192.168.3.0/24
        action: transfer

Dynamic updates
===============

Dynamic updates for the zone are allowed via proper ACL rule with the
``update`` action. If the zone is configured as a slave and DNS update
message is accepted, the server forwards the message to its primary master.
The master's response is then forwarded back to the originator.

However, if the zone is configured as master, the update is accepted and
processed::

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
configure :ref:`server_rate-limit-slip` interval, which causes every N\ :sup:`th`
blocked response to be slipped as a truncated response::

    server:
        rate-limit: 200     # Each flow is allowed to 200 resp. per second
        rate-limit-slip: 1  # Every response is slipped

.. _dnssec:

Automatic DNSSEC signing
========================

Knot DNS supports automatic DNSSEC signing for static zones. The signing
can operate in two modes:

1. :ref:`Manual key management <dnssec-manual-key-management>`.
   In this mode, the server maintains zone signatures only. The signatures
   are kept up-to-date and signing keys are rolled according to timing
   parameters assigned to the keys. The keys must be generated by the zone
   operator.

2. :ref:`Automatic key management <dnssec-automatic-key-management>`.
   In this mode, the server also maintains singing keys. New keys are generated
   according to assigned policy and are rolled automatically in a safe manner.
   No zone operator intervention is necessary.

The DNSSEC signing is controlled by the :ref:`zone_dnssec-signing` and
:ref:`zone_kasp_db` configuration options. The first option states
if the signing is enabled for a particular zone, the second option points to
a KASP database holding the signing configuration.

.. _dnssec-example:

Example configuration
---------------------

The example configuration enables automatic signing for all zones in the
default template, but the signing is explicitly disabled for zone
``example.dev``. The KASP database is common for all zones::

    template:
      - id: default
        dnssec-signing: on
        kasp-db: /var/lib/knot/kasp

    zone:
      - domain: example.com
        file: example.com.zone

      - domain: example.dev
        file: example.dev.zone
        dnssec-signing: off

.. _dnssec-kasp:

DNSSEC KASP database
--------------------

The configuration for DNSSEC is stored in a :abbr:`KASP (Key And Signature
Policy)` database. The database is simply a directory on the file-system
containing files in the JSON format. The database contains

- definitions of signing policies;
- zones configuration; and
- private key material.

The :doc:`keymgr <man_keymgr>` utility serves for the database maintenance.
To initialize the database, run:

.. code-block:: console

  $ mkdir -p /var/lib/knot/kasp
  $ cd /var/lib/knot/kasp
  $ keymgr init

.. ATTENTION::
  Make sure to set the KASP database permissions correctly. For manual key
  management, the database must be **readable** by the server process. For
  automatic key management, it must be **writeable**. The database also
  contains private key material -- don't set the permissions too loose.

.. _dnssec-automatic-key-management:

Automatic key management
------------------------

For automatic key management, a signing policy has to be defined in the
first place. This policy specifies how a zone is signed (i.e. signing
algorithm, key size, signature lifetime, key lifetime, etc.).

To create a new policy named *default_rsa* using *RSA-SHA-256* algorithm for
signing keys, 1024-bit long ZSK, and 2048-bit long KSK, run:

.. code-block:: console

  $ keymgr policy add default_rsa algorithm RSASHA256 zsk-size 1024 ksk-size 2048

The unspecified policy parameters are set to defaults. The complete definition
of the policy will be printed after executing the command.

Next, create a zone entry for zone *myzone.test* and assign it the newly
created policy:

.. code-block:: console

  $ keymgr zone add myzone.test policy default_rsa

Make sure everything is set correctly:

.. code-block:: console

  $ keymgr policy show default_rsa
  $ keymgr zone show myzone.test

Add the zone into the server configuration and enable DNSSEC for that zone.
The configuration fragment might look similar to::

  template:
    - id: default
      storage: /var/lib/knot
      kasp-db: kasp

  zone:
    - domain: myzone.test
      dnssec-signing: on

Finally, reload the server:

.. code-block:: console

  $ knotc reload

The server will generate initial signing keys and sign the zone properly. Check
the server logs to see whether everything went well.

.. ATTENTION::
  This guide assumes that the zone *myzone.test* was not signed prior to
  enabling the automatic key management. If the zone was already signed, all
  existing keys must be imported using ``keymgr zone key import`` command
  before reloading the server. Also the algorithm in the policy must match
  the algorithm of all imported keys.

.. _dnssec-manual-key-management:

Manual key management
---------------------

For automatic DNSSEC signing with manual key management, a signing policy
need not be defined.

Create a zone entry for the zone *myzone.test* without a policy:

.. code-block:: console

  $ keymgr zone add myzone.test

Generate a signing keys for the zone. Let's use the Single-Type Signing scheme
with two algorithms (this scheme is not supported in automatic key management).
Run:

.. code-block:: console

  $ keymgr zone key generate myzone.test algorithm RSASHA256 size 1024
  $ keymgr zone key generate myzone.test algorithm ECDSAP256SHA256 size 256

Enable automatic DNSSEC signing for the zone in the server configuration and
reload the server. Use the same steps as in
:ref:`dnssec-automatic-key-management`.

To perform a manual rollover of a key, the timing parameters of the key need
to be set. Let's roll the RSA key. Generate a new RSA key, but do not activate
it yet:

.. code-block:: console

  $ keymgr zone key generate myzone.test algorithm RSASHA256 size 1024 activate +1d

Take the key ID (or key tag) of the old RSA key and disable it the same time
the new key gets activated:

.. code-block:: console

  $ keymgr zone key set myzone.test <old_key_id> retire +1d remove +1d

Reload the server again. The new key gets published. Do not forget to update
the DS record in the parent zone to include the reference to the new RSA key.
This must happen in one day (in this case) including a delay required to
propagate the new DS to caches.

Note that as the ``+1d`` time specification is computed from the current time,
the key replacement will not happen at once. First, a new key will be
activated.  A few moments later, the old key will be deactivated and removed.
You can use exact time specification to make these two actions happen in one
go.

.. _dnssec-signing-policy:

Signing policy
--------------

The signing policy used in the KASP database defines parameters, how the zone
signatures and keys should be handled. At the moment, the policy comprises
of the following parameters:

Signing algorithm
  An algorithm of signing keys and issued signatures. The default value is
  *RSA-SHA-256*.

:abbr:`KSK (Key Signing Key)` size
  Desired length of the newly generated ZSK keys. The default value is 2048
  bits.

:abbr:`ZSK (Zone Signing Key)` size
  Desired length of the newly generated ZSK keys. The default value is 1024
  bits.

DNSKEY TTL
  TTL value for DNSKEY records added into zone apex. This parameter is
  temporarily overridden by the TTL value of the zone SOA record and thus
  has no default value.

ZSK lifetime
  Interval after which the ZSK rollover will be initiated. The default value
  is 30 days.

RRSIG lifetime
  Lifetime of newly issued signatures. The default value is 14 days.

RRSIG refresh
  Specifies how long before a signature expiration the signature will be
  refreshed. The default value is 7 days.

NSEC3
  Specifies if NSEC3 will be used instead of NSEC. This value is temporarily
  ignored. The setting is derived from the NSEC3PARAM record presence in the
  zone. The default value has not been decided yet.

SOA minimum TTL
  Specifies the SOA Minimum TTL field value. This option is required for
  correct key rollovers. The value has no real meaning with Knot DNS because
  the server will use a real value from the zone.

Zone maximum TTL
  Maximum TTL value present in the zone. This option is required for correct
  key rollovers. Knot DNS will determine the value automatically in the future.

Propagation delay
  An extra delay added for each key rollover step. This value should be high
  enough to cover propagation of data from the master server to all slaves.
  The default value is 1 hour.

.. _dnssec-signing:

Zone signing
------------

The signing process consists of the following steps:

#. Processing KASP database events. (e.g. performing a step of a rollover).
#. Fixing the NSEC or NSEC3 chain.
#. Updating the DNSKEY records. The whole DNSKEY set in zone apex is replaced
   by the keys from the KASP database. Note that keys added into the zone file
   manually will be removed. To add an extra DNSKEY record into the set, the
   key must be imported into the KASP database (possibly deactivated).
#. Removing expired signatures, invalid signatures, signatures expiring
   in a short time, and signatures issued by unknown key.
#. Creating missing signatures. Unless the Single-Type Signing Scheme
   is used, DNSKEY records in a zone apex are signed by KSK keys and
   all other records are signed by ZSK keys.
#. Updating and resigning SOA record.

The signing is initiated on the following occasions:

- Start of the server
- Zone reload
- Reaching the signature refresh period
- Received DDNS update
- Forced zone resign issued with ``knotc signzone``

On forced zone resign, all signatures in the zone are dropped and recreated.

The ``knotc zonestatus`` command can be used to see when the next scheduled
DNSSEC resign will happen.

.. _dnssec-limitations:

Limitations
-----------

The current DNSSEC implementation in Knot DNS has a bunch of limitations. Most
of the limitations will be hopefully removed in a near future.

- Automatic key management:

  - Only one DNSSEC algorithm can be used at a time for one zone.
  - Single-Type Signing scheme is not supported.
  - ZSK rollover always uses key pre-publish method (actually a feature).
  - KSK rollover is not implemented.

- Manual key management:

  - Default values for signature lifetime are forced.

- NSEC3:

  - Use of NSEC3 is determined by the presence of NSEC3PARAM in the zone.
  - Automatic re-salt is not implemented.

- KASP policy:

  - DNSKEY TTL value is overridden by the SOA TTL.
  - NSEC3 related parameters are ignored.
  - Zone maximum TTL is not determined automatically.

- Signing:

  - Signature expiration jitter is not implemented.
  - Signature expiration skew is not implemented.

- Utilities:

  - Legacy key import requires private key.
  - Legacy key export is not implemented.
  - DS record export is not implemented.

Query modules
=============

Knot DNS supports configurable query modules that can alter the way
queries are processed. The concept is quite simple -- each query
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
through :ref:`zone_module` option (in the form of ``module_name/module_id``)
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

This module is able to synthesize either forward or reverse records for
given prefix and subnet.

Records are synthesized only if the query can't be satisfied from the zone.
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
       network: 2620:0:b61::/52

   zone:
     - domain: example.
       file: example.zone # Zone file have to exist!
       module: mod-synth-record/test1

Result:

.. code-block:: console

   $ kdig AAAA dynamic-2620-0000-0b61-0100-0000-0000-0000-0000.example.
   ...
   ;; QUESTION SECTION:
   ;; dynamic-2620-0000-0b61-0100-0000-0000-0000-0000.example. 0	IN	AAAA

   ;; ANSWER SECTION:
   dynamic-2620-0000-0b61-0100... 400 IN AAAA 2620:0:b61:100::

You can also have CNAME aliases to the dynamic records, which are going to be
further resoluted:

.. code-block:: console

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
       origin: example
       ttl: 400
       network: 2620:0:b61::/52

   zone:
     - domain: 1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.
       file: 1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.zone # Zone file have to exist!
       module: mod-synth-record/test2

Result:

.. code-block:: console

   $ kdig PTR 1.0.0...1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.
   ...
   ;; QUESTION SECTION:
   ;; 1.0.0...1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa. 0	IN	PTR

   ;; ANSWER SECTION:
   ... 400 IN PTR dynamic-2620-0000-0b61-0000-0000-0000-0000-0001.example.

Limitations
^^^^^^^^^^^

* As of now, there is no authenticated denial of nonexistence (neither
  NSEC or NSEC3 is supported) nor DNSSEC signed records. However,
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

For example, suppose we have a database of following records:

.. code-block:: none

   myrecord.com.      3600 IN A 127.0.0.1
   www.myrecord.com.  3600 IN A 127.0.0.2
   ipv6.myrecord.com. 3600 IN AAAA ::1

And we query the nameserver with following:

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

*Note: An entry in the database matches anything at or below it,
i.e. 'myrecord.com' matches 'a.a.myrecord.com' as well.
This can be exploited to create a catch-all entries.*

You can also add an authority information for the entries, provided you create
a SOA + NS records for a name, like so:

.. code-block:: none

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

* Create the entries in the database:

  .. code-block:: console

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

* Start the server:

  .. code-block:: console

   $ knotd -c knot.conf

* Verify the running instance:

  .. code-block:: console

   $ kdig @127.0.0.1#6667 A myrecord.com
