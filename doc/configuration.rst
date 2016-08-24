.. highlight:: none
.. _Configuration:

*************
Configuration
*************

Simple configuration
====================

The following example presents a simple configuration file
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

Now let's walk through this configuration step by step:

- The :ref:`server_listen` statement in the :ref:`server section<Server section>`
  defines where the server will listen for incoming connections.
  We have defined the server to listen on all available IPv4 and IPv6 addresses,
  all on port 53.
- The :ref:`zone section<Zone section>` defines the zones that the server will
  serve. In this case, we defined one zone named *example.com* which is stored
  in the zone file :file:`/var/lib/knot/zones/example.com.zone`.
- The :ref:`log section<Logging section>` defines the log facilities for
  the server. In this example, we told Knot DNS to send its log messages with
  the severity ``info`` or more serious to the syslog.

For detailed description of all configuration items see
:ref:`Configuration Reference`.

Zone templates
==============

A zone template allows a single zone configuration to be shared among several zones.
Each template option can be explicitly overridden in zone-specific configurations.
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

An ACL list specifies which remotes are allowed to send the server a specific
request. A remote can be a single IP address or a network subnet. Also a TSIG
key can be assigned (see :doc:`keymgr <man_keymgr>` how to generate a TSIG key)::

    key:
      - id: key1
        algorithm: hmac-md5
        secret: Wg==

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
only requirement is to have a :ref:`master<zone_master>` statement set for
the given zone. Also note that you need to explicitly allow incoming zone
changed notifications via ``notify`` :ref:`acl_action` through zone's
:ref:`zone_acl` list, otherwise the update will be rejected by the server.
If the zone file doesn't exist it will be bootstrapped over AXFR::

    remote:
      - id: master
        address: 192.168.1.1@53

    acl:
      - id: notify_from_master
        address: 192.168.1.1
        action: notify

    zone:
      - domain: example.com
        storage: /var/lib/knot/zones/
        # file: example.com.zone   # Default value
        master: master
        acl: notify_from_master

Note that the :ref:`zone_master` option accepts a list of multiple remotes.
The remotes should be listed according to their preference. The first remote
has the highest preference, the other remotes are used for failover. When the
server receives a zone update notification from a listed remote, that remote
will be the most preferred one for the subsequent transfer.

To use TSIG for transfers and notification messages authentication, configure
a TSIG key and assign the key both to the remote and the ACL rule. Notice that
the :ref:`remote <Remote section>` and :ref:`ACL <ACL section>` definitions are
independent::

    key:
      - id: slave1_key
        algorithm: hmac-md5
        secret: Wg==

    remote:
      - id: master
        address: 192.168.1.1@53
        key: slave1_key

    acl:
      - id: notify_from_master
        address: 192.168.1.1
        key: slave1_key
        action: notify

.. NOTE::
   When transferring a lot of zones, the server may easily get into a state
   when all available ports are in the TIME_WAIT state, thus the transfers
   seize until the operating system closes the ports for good. There are
   several ways to work around this:

   * Allow reusing of ports in TIME_WAIT (sysctl -w net.ipv4.tcp_tw_reuse=1)
   * Shorten TIME_WAIT timeout (tcp_fin_timeout)
   * Increase available local port count

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

Optionally, a TSIG key can be specified::

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
``update`` action. If the zone is configured as a slave and a DNS update
message is accepted, the server forwards the message to its primary master.
The master's response is then forwarded back to the originator.

However, if the zone is configured as a master, the update is accepted and
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

Response rate limiting (RRL) is a method to combat DNS reflection amplification
attacks. These attacks rely on the fact that source address of a UDP query
can be forged, and without a worldwide deployment of `BCP38
<https://tools.ietf.org/html/bcp38>`_, such a forgery cannot be prevented.
An attacker can use a DNS server (or multiple servers) as an amplification
source and can flood a victim with a large number of unsolicited DNS responses.

The RRL lowers the amplification factor of these attacks by sending some of
the responses as truncated or by dropping them altogether.

You can enable RRL by setting the :ref:`server_rate-limit` option in the
:ref:`server section<Server section>`. The option controls how many responses
per second are permitted for each flow. Responses exceeding this rate are
limited. The option :ref:`server_rate-limit-slip` then configures how many
limited responses are sent as truncated (slip) instead of being dropped.

::

    server:
        rate-limit: 200     # Allow 200 resp/s for each flow
        rate-limit-slip: 2  # Every other response slips

.. _dnssec:

Automatic DNSSEC signing
========================

Knot DNS supports automatic DNSSEC signing for static zones. The signing
can operate in two modes:

1. :ref:`Automatic key management <dnssec-automatic-key-management>`.
   In this mode, the server maintains signing keys. New keys are generated
   according to assigned policy and are rolled automatically in a safe manner.
   No zone operator intervention is necessary.

2. :ref:`Manual key management <dnssec-manual-key-management>`.
   In this mode, the server maintains zone signatures only. The signatures
   are kept up-to-date and signing keys are rolled according to timing
   parameters assigned to the keys. The keys must be generated and timing
   parameters must be assigned by the zone operator.

The DNSSEC signing process maintains some metadata which is stored in the
:abbr:`KASP (Key And Signature Policy)` database. This database is simply
a directory in the file-system containing files in the JSON format.

.. WARNING::
  Make sure to set the KASP database permissions correctly. For manual key
  management, the database must be *readable* by the server process. For
  automatic key management, it must be *writeable*. If no HSM is used,
  the database also contains private key material – don't set the permissions
  too week.

.. _dnssec-automatic-key-management:

Automatic key management
------------------------

For automatic key management, a signing policy has to be configured and
assigned to the zone. The policy specifies how the zone is signed (i.e. signing
algorithm, key size, key lifetime, signature lifetime, etc.). The policy can
be configured in the :ref:`policy section <Policy section>`, or a ``default``
policy with the default parameters can be used.

A minimal zone configuration may look as follows::

  zone:
    - domain: myzone.test
      dnssec-signing: on
      dnssec-policy: default

With custom signing policy, the policy section will be added::

  policy:
    - id: rsa
      algorithm: RSASHA256
      ksk-size: 2048
      zsk-size: 1024

  zone:
    - domain: myzone.test
      dnssec-signing: on
      dnssec-policy: rsa

After configuring the server, reload the changes:

.. code-block:: console

  $ knotc reload

The server will generate initial signing keys and sign the zone properly. Check
the server logs to see whether everything went well.

.. WARNING::
  This guide assumes that the zone *myzone.test* was not signed prior to
  enabling the automatic key management. If the zone was already signed, all
  existing keys must be imported using ``keymgr zone key import`` command
  before enabling the automatic signing. Also the algorithm in the policy must
  match the algorithm of all imported keys. Otherwise the zone will be resigned
  at all.

.. _dnssec-manual-key-management:

Manual key management
---------------------

For automatic DNSSEC signing with manual key management, a signing policy
with manual key management flag has to be set::

  policy:
    - id: manual
      manual: on

  zone:
    - domain: myzone.test
      dnssec-signing: on
      dnssec-policy: manual

To generate signing keys, use the :doc:`keymgr <man_keymgr>` utility.
Let's use the Single-Type Signing scheme with two algorithms, which is
a scheme currently not supported by the automatic key management. Run:

.. code-block:: console

  $ keymgr zone key generate myzone.test algorithm RSASHA256 size 1024
  $ keymgr zone key generate myzone.test algorithm ECDSAP256SHA256 size 256

And reload the server. The zone will be signed.

To perform a manual rollover of a key, the timing parameters of the key need
to be set. Let's roll the RSA key. Generate a new RSA key, but do not activate
it yet:

.. code-block:: console

  $ keymgr zone key generate myzone.test algorithm RSASHA256 size 1024 active +1d

Take the key ID (or key tag) of the old RSA key and disable it the same time
the new key gets activated:

.. code-block:: console

  $ keymgr zone key set myzone.test <old_key_id> retire +1d remove +1d

Reload the server again. The new key will be published (i.e. the DNSKEY record
will be added into the zone). Do not forget to update the DS record in the
parent zone to include a reference to the new RSA key. This must happen in one
day (in this case) including a delay required to propagate the new DS to
caches.

Note that as the ``+1d`` time specification is computed from the current time,
the key replacement will not happen at once. First, a new key will be
activated.  A few moments later, the old key will be deactivated and removed.
You can use exact time specification to make these two actions happen in one
go.

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
   in a short time, and signatures issued by an unknown key.
#. Creating missing signatures. Unless the Single-Type Signing Scheme
   is used, DNSKEY records in a zone apex are signed by KSK keys and
   all other records are signed by ZSK keys.
#. Updating and resigning SOA record.

The signing is initiated on the following occasions:

- Start of the server
- Zone reload
- Reaching the signature refresh period
- Received DDNS update
- Forced zone resign via server control interface

On a forced zone resign, all signatures in the zone are dropped and recreated.

The ``knotc zone-status`` command can be used to see when the next scheduled
DNSSEC resign will happen.

.. _dnssec-limitations:

Limitations
-----------

The current DNSSEC implementation in Knot DNS has some limitations. Most
of the limitations will be hopefully removed in the near future.

- Automatic key management:

  - Only one DNSSEC algorithm can be used per zone.
  - Single-Type Signing scheme is not supported.
  - ZSK rollover always uses key pre-publish method (actually a feature).
  - KSK rollover is not implemented.

- Signing:

  - Signature expiration jitter is not implemented.
  - Signature expiration skew is not implemented.

- Utilities:

  - Legacy key import requires a private key.
  - Legacy key export is not implemented.
  - DS record export is not implemented.

Query modules
=============

Knot DNS supports configurable query modules that can alter the way
queries are processed. The concept is quite simple – each query
requires a finite number of steps to be resolved. We call this set of
steps a *query plan*, an abstraction that groups these steps into
several stages.

* Before-query processing
* Answer, Authority, Additional records packet sections processing
* After-query processing

For example, processing an Internet-class query needs to find an
answer. Then based on the previous state, it may also append an
authority SOA or provide additional records. Each of these actions
represents a 'processing step'. Now, if a query module is loaded for a
zone, it is provided with an implicit query plan which can be extended
by the module or even changed altogether.

Each module is configured in the corresponding module section and is
identified for the subsequent usage. Then the identifier is referenced
in the form of ``module_name/module_id`` through a zone/template :ref:`zone_module`
option or through the *default* template :ref:`template_global-module` option
if it is used for all queries.

``dnstap`` – dnstap-enabled query logging
-----------------------------------------

A module for query and response logging based on dnstap_ library.
You can capture either all or zone-specific queries and responses; usually
you want to do the former. The configuration comprises only a
:ref:`mod-dnstap_sink` path parameter, which can be either a file or
a UNIX socket::

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

``synth-record`` – Automatic forward/reverse records
----------------------------------------------------

This module is able to synthesize either forward or reverse records for
a given prefix and subnet.

Records are synthesized only if the query can't be satisfied from the zone.
Both IPv4 and IPv6 are supported.

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
     - domain: test.
       file: test.zone # Must exist
       module: mod-synth-record/test1

Result:

.. code-block:: console

   $ kdig AAAA dynamic-2620-0000-0b61-0100-0000-0000-0000-0001.test.
   ...
   ;; QUESTION SECTION:
   ;; dynamic-2620-0000-0b61-0100-0000-0000-0000-0001.test. IN AAAA

   ;; ANSWER SECTION:
   dynamic-2620-0000-0b61-0100-0000-0000-0000-0001.test. 400 IN AAAA 2620:0:b61:100::1

You can also have CNAME aliases to the dynamic records, which are going to be
further resolved:

.. code-block:: console

   $ kdig AAAA alias.test.
   ...
   ;; QUESTION SECTION:
   ;; alias.test. IN AAAA

   ;; ANSWER SECTION:
   alias.test. 3600 IN CNAME dynamic-2620-0000-0b61-0100-0000-0000-0000-0002.test.
   dynamic-2620-0000-0b61-0100-0000-0000-0000-0002.test. 400 IN AAAA 2620:0:b61:100::2

Automatic reverse records
-------------------------

Example::

   mod-synth-record:
     - id: test2
       type: reverse
       prefix: dynamic-
       origin: test
       ttl: 400
       network: 2620:0:b61::/52

   zone:
     - domain: 1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.
       file: 1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa.zone # Must exist
       module: mod-synth-record/test2

Result:

.. code-block:: console

   $ kdig -x 2620:0:b61::1
   ...
   ;; QUESTION SECTION:
   ;; 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa. IN PTR

   ;; ANSWER SECTION:
   1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.6.b.0.0.0.0.0.0.2.6.2.ip6.arpa. 400 IN PTR
                                  dynamic-2620-0000-0b61-0000-0000-0000-0000-0001.test.

``dnsproxy`` – Tiny DNS proxy
-----------------------------

The module catches all unsatisfied queries and forwards them to the
indicated server for resolution, i.e. a tiny DNS proxy. There are several
uses of this feature:

* A substitute public-facing server in front of the real one
* Local zones (poor man's "views"), rest is forwarded to the public-facing server
* etc.

.. NOTE::
   The module does not alter the query/response as the resolver would,
   and the original transport protocol is kept as well.

The configuration is straightforward and just a single remote server is
required::

   remote:
     - id: hidden
       address: 10.0.1.1

   mod-dnsproxy:
     - id: default
       remote: hidden

   template:
     - id: default
       global-module: mod-dnsproxy/default

   zone:
     - domain: local.zone

When clients query for anything in the ``local.zone``, they will be
responded to locally. The rest of the requests will be forwarded to the
specified server (``10.0.1.1`` in this case).

``rosedb`` – Static resource records
------------------------------------

The module provides a mean to override responses for certain queries before
the record is searched in the available zones. The module comes with the
``rosedb_tool`` tool used to manipulate the database of static records.
Neither the tool nor the module are enabled by default, recompile with
the ``--enable-rosedb`` configuration flag to enable them.

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
subtree isolation for each entry.*

In addition, the module is able to log matching queries via remote syslog if
you specify a syslog address endpoint and an optional string code.

Here is an example on how to use the module:

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

``online-sign`` — Online DNSSEC signing
---------------------------------------

The module provides online DNSSEC signing. Instead of pre-computing the zone
signatures when the zone is loaded into the server or instead of loading an
externally signed zone, the signatures are computed on-the-fly during
answering.

The main purpose of the module is to enable authenticated responses with
zones which use other dynamic module (e.g., automatic reverse record
synthesis) because these zones cannot be pre-signed. However, it can be also
used as a simple signing solution for zones with low traffic and also as
a protection against zone content enumeration (zone walking).

In order to minimize the number of computed signatures per query, the module
produces a bit different responses from the responses that would be sent if
the zone was pre-signed. Still, the responses should be perfectly valid for
a DNSSEC validating resolver.

Differences from statically signed zones:

* The NSEC records are constructed as Minimally Covering NSEC Records
  (see Appendix A in :rfc:`7129`). Therefore the generated domain names cover
  the complete domain name space in the zone's authority.

* NXDOMAIN responses are promoted to NODATA responses. The module proves
  that the query type does not exist rather than that the domain name does not
  exist.

* Domain names matching a wildcard are expanded. The module pretends and proves
  that the domain name exists rather than proving a presence of the wildcard.

Records synthesized by the module:

* DNSKEY record is synthesized in the zone apex and includes public key
  material for the active signing key.

* NSEC records are synthesized as needed.

* RRSIG records are synthesized for authoritative content of the zone.

How to use the online signing module:

* First add the zone into the server's KASP database and generate a key to be
  used for signing:

  .. code-block:: console

   $ cd /path/to/kasp
   $ keymgr zone add example.com
   $ keymgr zone key generate example.com algorithm ecdsap256sha256 size 256

* Enable the module in server configuration and hook it to the zone::

   mod-online-sign:
     - id: default

   zone:
     - domain: example.com
       module: mod-online-sign/default
       dnssec-signing: false

* Make sure the zone is not signed and also that the automatic signing is
  disabled. All is set, you are good to go. Reload (or start) the server:

  .. code-block:: console

   $ knotc reload

The following example stacks the online signing with reverse record synthesis
module::

 mod-online-sign:
   - id: default

 mod-synth-record:
   - id: lan-forward
     type: forward
     prefix: ip-
     ttl: 1200
     network: 192.168.100.0/24

 template:
   - id: default
     dnssec-signing: false

 zone:
   - domain: corp.example.net
     module: mod-synth-record/lan-forward
     module: mod-online-sign/default

Known issues:

* The delegations are not signed correctly.

* Some CNAME records are not signed correctly.

Limitations:

* Only a Single-Type Signing scheme is supported.

* Only one active signing key can be used.

* Key rollover is not possible.

* The NSEC records may differ for one domain name if queried for different
  types. This is an implementation shortcoming as the dynamic modules
  cooperate loosely. Possible synthesis of a type by other module cannot
  be predicted. This dissimilarity should not affect response validation,
  even with validators performing `aggressive negative caching
  <https://datatracker.ietf.org/doc/draft-fujiwara-dnsop-nsec-aggressiveuse/>`_.

* The NSEC proofs will work well with other dynamic modules only if the
  modules synthesize only A and AAAA records. If synthesis of other type
  is required, please, report this information to Knot DNS developers.

``whoami`` — whoami module
--------------------------

The module synthesizes an A or AAAA record containing the query source IP address,
at the apex of the zone being served. It makes sure to allow Knot DNS to generate
cacheable negative responses, and to allow fallback to extra records defined in the
underlying zone file. The TTL of the synthesized record is copied from
the TTL of the SOA record in the zone file.

Because a DNS query for type A or AAAA has nothing to do with whether
the query occurs over IPv4 or IPv6, this module requires a special
zone configuration to support both address families. For A queries, the
underlying zone must have a set of nameservers that only have IPv4
addresses, and for AAAA queries, the underlying zone must have a set of
nameservers that only have IPv6 addresses.

To enable this module, you need to add something like the following to
the Knot DNS configuration file::

    mod-whoami:
      - id: default

    zone:
      - domain: whoami.domain.example
        file: "/path/to/whoami.domain.example"
        module: [mod-whoami/default]

    zone:
      - domain: whoami6.domain.example
        file: "/path/to/whoami6.domain.example"
        module: [mod-whoami/default]

The whoami.domain.example zone file example:

  .. code-block:: none

    $TTL 1

    @       SOA     (
                            whoami.domain.example.          ; MNAME
                            hostmaster.domain.example.      ; RNAME
                            2016051300                      ; SERIAL
                            86400                           ; REFRESH
                            86400                           ; RETRY
                            86400                           ; EXPIRE
                            1                               ; MINIMUM
                    )

    $TTL 86400

    @       NS      ns1.whoami.domain.example.
    @       NS      ns2.whoami.domain.example.
    @       NS      ns3.whoami.domain.example.
    @       NS      ns4.whoami.domain.example.

    ns1     A       198.51.100.53
    ns2     A       192.0.2.53
    ns3     A       203.0.113.53
    ns4     A       198.19.123.53

The whoami6.domain.example zone file example:

  .. code-block:: none

    $TTL 1

    @       SOA     (
                            whoami6.domain.example.         ; MNAME
                            hostmaster.domain.example.      ; RNAME
                            2016051300                      ; SERIAL
                            86400                           ; REFRESH
                            86400                           ; RETRY
                            86400                           ; EXPIRE
                            1                               ; MINIMUM
                    )

    $TTL 86400

    @       NS      ns1.whoami6.domain.example.
    @       NS      ns2.whoami6.domain.example.
    @       NS      ns3.whoami6.domain.example.
    @       NS      ns4.whoami6.domain.example.

    ns1     AAAA    2001:db8:100::53
    ns2     AAAA    2001:db8:200::53
    ns3     AAAA    2001:db8:300::53
    ns4     AAAA    2001:db8:400::53

The parent domain would then delegate whoami.domain.example to
ns[1-4].whoami.domain.example and whoami6.domain.example to
ns[1-4].whoami6.domain.example, and include the corresponding A-only or
AAAA-only glue records.
