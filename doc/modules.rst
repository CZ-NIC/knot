.. highlight:: none
.. _Query_modules:

*************
Query modules
*************

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

A module is active if its name, which includes the ``mod-`` prefix, is assigned
to the zone/template :ref:`zone_module` option or to the *default* template
:ref:`template_global-module` option if activating for all queries.
If the module is configurable, a corresponding module section with
an identifier must be created and then referenced in the form of
``module_name/module_id``.

.. NOTE::
   Query modules are processed in the order they are specified in the
   zone/template configuration. In most cases, the recommended order is::

      mod-synth-record, mod-online-sign, mod-rrl, mod-dnstap, mod-stats

``rrl`` — Response rate limiting
--------------------------------

Response rate limiting (RRL) is a method to combat DNS reflection amplification
attacks. These attacks rely on the fact that source address of a UDP query
can be forged, and without a worldwide deployment of `BCP38
<https://tools.ietf.org/html/bcp38>`_, such a forgery cannot be prevented.
An attacker can use a DNS server (or multiple servers) as an amplification
source and can flood a victim with a large number of unsolicited DNS responses.
The RRL lowers the amplification factor of these attacks by sending some of
the responses as truncated or by dropping them altogether.

The module introduces two counters. The number of slipped and dropped responses.

You can enable RRL by setting the :ref:`mod-rrl<mod-rrl>` module globally or per zone.

::

    mod-rrl:
      - id: default
        rate-limit: 200   # Allow 200 resp/s for each flow
        slip: 2           # Every other response slips

    template:
      - id: default
        global-module: mod-rrl/default   # Enable RRL globally

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
.........................

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
.........................

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

   $ keymgr -d /path/to/kasp -l init
   $ keymgr -d /path/to/kasp -l zone add example.com
   $ keymgr -d /path/to/kasp -l zone key generate example.com algorithm ecdsap256sha256 size 256

* Enable the module in server configuration and hook it to the zone::

   zone:
     - domain: example.com
       module: mod-online-sign
       dnssec-signing: false

  .. NOTE::
     This module is not configurable.

* Make sure the zone is not signed and also that the automatic signing is
  disabled. All is set, you are good to go. Reload (or start) the server:

  .. code-block:: console

   $ knotc reload

The following example stacks the online signing with reverse record synthesis
module::

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
     module: [mod-synth-record/lan-forward, mod-online-sign]

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

    zone:
      - domain: whoami.domain.example
        file: "/path/to/whoami.domain.example"
        module: mod-whoami

    zone:
      - domain: whoami6.domain.example
        file: "/path/to/whoami6.domain.example"
        module: mod-whoami

.. NOTE::
   This module is not configurable.

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

``noudp`` — noudp module
------------------------

The module sends empty truncated response to any UDP query. This is similar
to a slipped answer in :ref:`response rate limiting<mod-rrl_rate-limit>`.
TCP queries are not affected.

To enable this module globally, you need to add something like the following
to the configuration file::

    template:
      - id: default
        global-module: mod-noudp

.. NOTE::
   This module is not configurable.

``stats`` — query statistics
----------------------------

The module extends server statistics with incoming DNS request and corresponding
response counters, such as used network protocol, total number of responded bytes,
etc (see :ref:`mod-stats<mod-stats>` for full list of supported counters).
This module should be configured as the last module.

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

.. NOTE::
   Server initiated communication (outgoing NOTIFY, incoming \*XFR,...) is not
   counted by this module.

