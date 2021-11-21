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
  the severity ``info`` or more serious to the syslog (or systemd journal).

For detailed description of all configuration items see
:ref:`Configuration Reference`.

Zone templates
==============

A zone template allows a single zone configuration to be shared among several
zones. There is no inheritance between templates; they are exclusive. The
``default`` template identifier is reserved for the default template::

    template:
      - id: default
        storage: /var/lib/knot/master
        semantic-checks: on

      - id: signed
        storage: /var/lib/knot/signed
        dnssec-signing: on
        semantic-checks: on
        master: [master1, master2]

      - id: slave
        storage: /var/lib/knot/slave

    zone:
      - domain: example1.com     # Uses default template

      - domain: example2.com     # Uses default template
        semantic-checks: off     # Override default settings

      - domain: example.cz
        template: signed
        master: master3          # Override masters to just master3

      - domain: example1.eu
        template: slave
        master: master1

      - domain: example2.eu
        template: slave
        master: master2

.. NOTE::
   Each template option can be explicitly overridden in zone-specific configuration.

.. _ACL:

Access control list (ACL)
=========================

The Access control list is a list of rules specifying remotes which are allowed to
send certain types of requests to the server.
Remotes can be specified by a single IP address or a network subnet. A TSIG
key can also be assigned (see :doc:`keymgr<man_keymgr>` on how to generate a TSIG key).

Without any ACL rules, all the actions are denied for the zone. Each ACL rule
can allow one or more actions for a given address/subnet/TSIG, or deny them.

If there are multiple ACL rules for a single zone, they are applied in the order
of appearance in the :ref:`zone_acl` configuration item of a zone or a template.
The first one to match the given remote is applied, the rest is ignored.

For dynamic updates, additional rules may be specified, which will allow or deny updates
according to the type or owner of Resource Records in the update.

See the following examples and :ref:`ACL section`.

::

    acl:
      - id: address_rule
        address: [2001:db8::1, 192.168.2.0/24]
        action: transfer

      - id: deny_rule
        address: 192.168.2.100
        action: transfer
        deny: on

    zone:
      - domain: acl1.example.com.
        acl: [deny_rule, address_rule] # deny_rule first here to take precedence

::

    key:
      - id: key1                  # The real TSIG key name
        algorithm: hmac-md5
        secret: Wg==

    acl:
      - id: deny_all
        address: 192.168.3.0/24
        deny: on # no action specified and deny on implies denial of all actions

      - id: key_rule
        key: key1                 # Access based just on TSIG key
        action: [transfer, notify]

    zone:
      - domain: acl2.example.com
        acl: [deny_all, key_rule]

::

    acl:
        - id: owner_type_rule
          action: update
          update-type: [A, AAAA, MX] # Updates are only allowed to update records of the specified types
          update-owner: name         # The allowed owners are specified by the list on the next line
          update-owner-name: [a, b.example.com.] # Non-FQDN names are relative to the effective zone name
          update-owner-match: equal  # The owners of records in an update must be exactly equal to the names in the list

.. NOTE::
   If more conditions (address ranges and/or a key)
   are given in a single ACL rule, all of them have to be satisfied for the rule to match.

.. TIP::
   In order to restrict regular DNS queries, use module :ref:`queryacl<mod-queryacl>`.

Secondary (slave) zone
======================

Knot DNS doesn't strictly differ between primary (formerly known as master)
and secondary (formerly known as slave) zones. The only requirement for a secondary
zone is to have a :ref:`zone_master` statement set. Also note that you need
to explicitly allow incoming zone changed notifications via ``notify`` :ref:`acl_action`
through a zone's :ref:`zone_acl` list, otherwise the update will be rejected by the
server. If the zone file doesn't exist it will be bootstrapped over AXFR::

    remote:
      - id: master
        address: 192.168.1.1@53
        # via: 10.0.0.1            # Specify local source address if needed

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
   where all available ports are in the TIME_WAIT state, thus transfers
   cease until the operating system closes the ports for good. There are
   several ways to work around this:

   * Allow reusing of ports in TIME_WAIT (sysctl -w net.ipv4.tcp_tw_reuse=1)
   * Shorten TIME_WAIT timeout (tcp_fin_timeout)
   * Increase available local port count

Primary (master) zone
=====================

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

Note that a secondary zone may serve as a primary zone at the same time::

    remote:
      - id: master
        address: 192.168.1.1@53
      - id: slave1
        address: 192.168.2.1@53

    acl:
      - id: notify_from_master
        address: 192.168.1.1
        action: notify

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
        master: master
        notify: slave1
        acl: [notify_from_master, slave1_acl, others_acl]

Dynamic updates
===============

Dynamic updates for the zone are allowed via proper ACL rule with the
``update`` action. If the zone is configured as a secondary and a DNS update
message is accepted, the server forwards the message to its primary master.
The primary master's response is then forwarded back to the originator.

However, if the zone is configured as a primary, the update is accepted and
processed::

    acl:
      - id: update_acl
        address: 192.168.3.0/24
        action: update

    zone:
      - domain: example.com
        file: example.com.zone
        acl: update_acl

.. _dnssec:

Automatic DNSSEC signing
========================

Knot DNS supports automatic DNSSEC signing of zones. The signing
can operate in two modes:

1. :ref:`Automatic key management <dnssec-automatic-zsk-management>`.
   In this mode, the server maintains signing keys. New keys are generated
   according to assigned policy and are rolled automatically in a safe manner.
   No zone operator intervention is necessary.

2. :ref:`Manual key management <dnssec-manual-key-management>`.
   In this mode, the server maintains zone signatures only. The signatures
   are kept up-to-date and signing keys are rolled according to timing
   parameters assigned to the keys. The keys must be generated and timing
   parameters must be assigned by the zone operator.

The DNSSEC signing process maintains some metadata which is stored in the
:abbr:`KASP (Key And Signature Policy)` database. This database is backed
by LMDB.

.. WARNING::
  Make sure to set the KASP database permissions correctly. For manual key
  management, the database must be *readable* by the server process. For
  automatic key management, it must be *writeable*. If no HSM is used,
  the database also contains private key material – don't set the permissions
  too weak.

.. _dnssec-automatic-zsk-management:

Automatic ZSK management
------------------------

For automatic ZSK management a signing :ref:`policy<Policy section>` has to
be configured and assigned to the zone. The policy specifies how the zone
is signed (i.e. signing algorithm, key size, key lifetime, signature lifetime,
etc.). If no policy is specified or the ``default`` one is assigned, the
default signing parameters are used.

A minimal zone configuration may look as follows::

  zone:
    - domain: myzone.test
      dnssec-signing: on

With a custom signing policy, the policy section will be added::

  policy:
    - id: custom_policy
      signing-threads: 4
      algorithm: ECDSAP256SHA256
      zsk-lifetime: 60d

  zone:
    - domain: myzone.test
      dnssec-signing: on
      dnssec-policy: custom_policy

After configuring the server, reload the changes:

.. code-block:: console

  $ knotc reload

The server will generate initial signing keys and sign the zone properly. Check
the server logs to see whether everything went well.

.. _dnssec-automatic-ksk-management:

Automatic KSK management
------------------------

For automatic KSK management, first configure ZSK management like above, and use
additional options in :ref:`policy section <Policy section>`, mostly specifying
desired (finite) lifetime for KSK: ::

  remote:
    - id: parent_zone_server
      address: 192.168.12.1@53

  submission:
    - id: parent_zone_sbm
      parent: [parent_zone_server]

  policy:
    - id: custom_policy
      signing-threads: 4
      algorithm: ECDSAP256SHA256
      zsk-lifetime: 60d
      ksk-lifetime: 365d
      ksk-submission: parent_zone_sbm

  zone:
    - domain: myzone.test
      dnssec-signing: on
      dnssec-policy: custom_policy

After the initially-generated KSK reaches its lifetime, new KSK is published and after
convenience delay the submission is started. The server publishes CDS and CDNSKEY records
and the user shall propagate them to the parent. The server periodically checks for
DS at the parent zone and when positive, finishes the rollover.

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

To generate signing keys, use the :doc:`keymgr<man_keymgr>` utility.
For example, we can use Single-Type Signing:

.. code-block:: console

  $ keymgr myzone.test. generate algorithm=ECDSAP256SHA256 ksk=yes zsk=yes

And reload the server. The zone will be signed.

To perform a manual rollover of a key, the timing parameters of the key need
to be set. Let's roll the key. Generate a new key, but do not activate
it yet:

.. code-block:: console

  $ keymgr myzone.test. generate algorithm=ECDSAP256SHA256 ksk=yes zsk=yes active=+1d

Take the key ID (or key tag) of the old key and disable it the same time
the new key gets activated:

.. code-block:: console

  $ keymgr myzone.test. set <old_key_id> retire=+2d remove=+3d

Reload the server again. The new key will be published (i.e. the DNSKEY record
will be added into the zone). Remember to update the DS record in the
parent zone to include a reference to the new key. This must happen within one
day (in this case) including a delay required to propagate the new DS to
caches.

.. WARNING::
   If you ever decide to switch from manual key management to automatic key management,
   note that the automatic key management uses
   :ref:`policy_zsk-lifetime` and :ref:`policy_ksk-lifetime` policy configuration
   options to schedule key rollovers and it internally uses timestamps of keys differently
   than in the manual case. As a consequence it might break if the ``retire`` or ``remove`` timestamps
   are set for the manually generated keys currently in use. Make sure to set these timestamps
   to zero using :doc:`keymgr<man_keymgr>`:

   .. code-block:: console

       $ keymgr myzone.test. set <key_id> retire=0 remove=0

   and configure your policy suitably according to :ref:`dnssec-automatic-zsk-management`
   and :ref:`dnssec-automatic-ksk-management`.

.. _dnssec-signing:

Zone signing
------------

The signing process consists of the following steps:

#. Processing KASP database events. (e.g. performing a step of a rollover).
#. Updating the DNSKEY records. The whole DNSKEY set in zone apex is replaced
   by the keys from the KASP database. Note that keys added into the zone file
   manually will be removed. To add an extra DNSKEY record into the set, the
   key must be imported into the KASP database (possibly deactivated).
#. Fixing the NSEC or NSEC3 chain.
#. Removing expired signatures, invalid signatures, signatures expiring
   in a short time, and signatures issued by an unknown key.
#. Creating missing signatures. Unless the Single-Type Signing Scheme
   is used, DNSKEY records in a zone apex are signed by KSK keys and
   all other records are signed by ZSK keys.
#. Updating and re-signing SOA record.

The signing is initiated on the following occasions:

- Start of the server
- Zone reload
- Reaching the signature refresh period
- Key set changed due to rollover event
- Received DDNS update
- Forced zone re-sign via server control interface

On a forced zone re-sign, all signatures in the zone are dropped and recreated.

The ``knotc zone-status`` command can be used to see when the next scheduled
DNSSEC re-sign will happen.

.. _dnssec-on-slave-signing:

On-secondary (on-slave) signing
-------------------------------

It is possible to enable automatic DNSSEC zone signing even on a secondary
server. If enabled, the zone is signed after every AXFR/IXFR transfer
from primary, so that the secondary always serves a signed up-to-date version
of the zone.

It is strongly recommended to block any outside access to the primary
server, so that only the secondary server's signed version of the zone is served.

Enabled on-secondary signing introduces events when the secondary zone changes
while the primary zone remains unchanged, such as a key rollover or
refreshing of RRSIG records, which cause inequality of zone SOA serial
between primary and secondary. The secondary server handles this by saving the
primary's SOA serial in a special variable inside KASP DB and appropriately
modifying AXFR/IXFR queries/answers to keep the communication with
primary server consistent while applying the changes with a different serial.

.. _catalog-zones:

Catalog zones
=============

Catalog zones are a concept whereby a list of zones to be configured is maintained
as contents of a separate, special zone. This approach has the benefit of simple
propagation of a zone list to secondary servers, especially when the list is
frequently updated. Currently, catalog zones are described in this `Internet Draft
<https://tools.ietf.org/html/draft-ietf-dnsop-dns-catalog-zones>`_.

Terminology first. *Catalog zone* is a meta-zone which shall not be a part
of the DNS tree, but it contains information about the set of member zones and
is transferable to secondary servers using common AXFR/IXFR techniques.
*Catalog-member zone* (or just *member zone*) is a zone based on
information from the catalog zone and not from configuration file/database.
*Member properties* are some additional information related to each member zone,
also distributed by the catalog zone.

A catalog zone is handled almost in the same way as a regular zone:
It can be configured using all the standard options (but for example
DNSSEC signing would be useless), including primary/secondary configuration
and ACLs. A catalog zone is indicated by setting the option
:ref:`zone_catalog-role`. The difference is that standard DNS
queries to a catalog zone are answered with REFUSED as though the zone
doesn't exist, unless querying over TCP from an address with transfers enabled
by ACL. The name of the catalog zone is arbitrary. It's possible to configure
multiple catalog zones.

.. WARNING::
   Don't choose a name for a catalog zone below a name of any other
   existing zones configured on the server as it would effectively "shadow"
   part of your DNS subtree.

Upon catalog zone (re)load or change, all the PTR records in the format
``unique-id.zones.catalog. 0 IN PTR member.com.`` (but not ``too.deep.zones.catalog.``!)
are processed and member zones created, with zone names taken from the
PTR records' RData, and zone settings taken from the configuration
templates specified by :ref:`zone_catalog-template`.

The owner names of the PTR records shall follow this scheme:

.. code-block:: console

    <unique-id>.zones.<catalog-zone>.

where the mentioned labels shall match:

- *<unique-id>* — Single label that is recommended to be unique among member zones.
- ``zones`` — Required label.
- *<catalog-zone>* — Name of the catalog zone.

Additionally, records in the format
``group.unique-id.zones.catalog. 0 IN TXT "conf-template"``
are processed as a definition of the member's *group* property. The
``unique-id`` must match the one of the PTR record defining the member.

All other records and other member properties are ignored. They remain in the catalog
zone, however, and might be for example transferred to a secondary server,
which may interpret catalog zones differently. SOA still needs to be present in
the catalog zone and its serial handled appropriately. An apex NS record should be
present for the sake of interoperability. The version record ``version 0 IN TXT "2"``
is required at the catalog zone apex.

A catalog zone may be modified using any standard means (e.g. AXFR/IXFR, DDNS,
zone file reload). In the case of incremental change, only affected
member zones are reloaded.

The catalog zone must have at least one :ref:`zone_catalog-template`
configured. The configuration for any defined member zone is taken from its
*group* property value, which should match some catalog-template name.
If the *group* property is not defined for a member, is empty, or doesn't match
any of defined catalog-template names, the first catalog-template
(in the order from configuration) is used.

Any de-cataloged member zone is purged immediately, including its
zone file, journal, timers, and DNSSEC keys. The zone file is not
deleted if :ref:`zone_zonefile-sync` is set to *-1* for member zones.
Any member zone, whose PTR record's owner has been changed, is purged
immediately if and only if the *<unique-id>* has been changed.

When setting up catalog zones, it might be useful to set
:ref:`database_catalog-db` and :ref:`database_catalog-db-max-size`
to non-default values.

.. NOTE::

   Whenever a catalog zone is updated, the server reloads itself with
   all configured zones, including possibly existing other catalog zones.
   It's similar to calling `knotc zone-reload` (for all zones).
   The consequence is that new zone files might be discovered and reloaded,
   even for zones that do not relate to updated catalog zone.

.. WARNING::

   The server does not work well if one member zone appears in two catalog zones
   concurrently. The user is encouraged to avoid this situation whatsoever.
   Thus, there is no way a member zone can be migrated from one catalog
   to another while preserving its metadata. Following steps may be used
   as a workaround:

   * :ref:`Back up<Data and metadata backup>` the member zone's metadata
     (on each server separately).
   * Remove the member zone from the catalog it's a member of.
   * Wait for the catalog zone to be propagated to all servers.
   * Add the member zone to the other catalog.
   * Restore the backed up metadata (on each server separately).

Catalog zones configuration examples
------------------------------------

Below are configuration snippets (e.g. `server` and `log` sections missing)
of very simple catalog zone setups, in order to illustrate the relations
between catalog-related configuration options.

First setup represents a very simple scenario where the primary is
the catalog zone generator and the secondary is the catalog zone consumer.

Primary configuration::

  acl:
    - id: slave_xfr
      address: ...
      action: transfer

  template:
    - id: mmemb
      catalog-role: member
      catalog-zone: catz.
      acl: slave_xfr

  zone:
    - domain: catz.
      catalog-role: generate
      acl: slave_xfr

    - domain: foo.com.
      template: mmemb

    - domain: bar.com.
      template: mmemb

Secondary configuration::

  acl:
    - id: master_notify
      address: ...
      action: notify

  template:
    - id: smemb
      master: master
      acl: master_notify

  zone:
    - domain: catz.
      master: master
      acl: master_notify
      catalog-role: interpret
      catalog-template: smemb

When new zones are added (or removed) to the primary configuration with assigned
`mmemb` template, they will automatically propagate to the secondary
and have the `smemb` template assigned there.

Second example is with a hand-written (or script-generated) catalog zone,
while employing configuration groups::

  catz.                   0       SOA     invalid. invalid. 1625079950 3600 600 2147483646 0
  catz.                   0       NS      invalid.
  version.catz.           0       TXT     "2"
  nj2xg5bnmz2w4ltd.zones.catz.       0       PTR     just-fun.com.
  group.nj2xg5bnmz2w4ltd.zones.catz. 0       TXT     unsigned
  nvxxezjnmz2w4ltd.zones.catz.       0       PTR     more-fun.com.
  group.nvxxezjnmz2w4ltd.zones.catz. 0       TXT     unsigned
  nfwxa33sorqw45bo.zones.catz.       0       PTR     important.com.
  group.nfwxa33sorqw45bo.zones.catz. 0       TXT     signed
  mjqw42zomnxw2lq0.zones.catz.       0       PTR     bank.com.
  group.mjqw42zomnxw2lq0.zones.catz. 0       TXT     signed

And the server in this case is configured to distinguish the groups by applying
different templates::

  template:
    - id: unsigned
      ...

    - id: signed
      dnssec-signing: on
      dnssec-policy: ...
      ...

  zone:
    - domain: catz.
      file: ...
      catalog-role: interpret
      catalog-template: [ unsigned, signed ]

.. _query-modules:

Query modules
=============

Knot DNS supports configurable query modules that can alter the way
queries are processed. Each query requires a finite number of steps to
be resolved. We call this set of steps a *query plan*, an abstraction
that groups these steps into several stages.

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
to the zone/template :ref:`zone_module` option or to the ``default`` template
:ref:`template_global-module` option if activating for all queries.
If the module is configurable, a corresponding module section with
an identifier must be created and then referenced in the form of
``module_name/module_id``. See :ref:`Modules` for the list of available modules.

.. NOTE::
   Query modules are processed in the order they are specified in the
   zone/template configuration. In most cases, the recommended order is::

      mod-synthrecord, mod-onlinesign, mod-cookies, mod-rrl, mod-dnstap, mod-stats

Performance Tuning
==================

Numbers of Workers
------------------

There are three types of workers ready for parallel execution of performance-oriented tasks:
UDP workers, TCP workers, and Background workers. The first two types handle all network requests
via the UDP and TCP protocol (respectively) and do the response jobs for common
queries. Background workers process changes to the zone.

By default, Knot determines a well-fitting number of workers based on the number of CPU cores.
The user can specify the number of workers for each type with configuration/server section:
:ref:`server_udp-workers`, :ref:`server_tcp-workers`, :ref:`server_background-workers`.

An indication of when to increase the number of workers is when the server is lagging behind
expected performance, while CPU usage remains low. This is usually due to waiting for network
or I/O response during the operation. It may be caused by Knot design not fitting the use-case well.
The user should try increasing the number of workers (of the related type) slightly above 100 and if
the performance improves, decide a further, exact setting.

Number of available file descriptors
------------------------------------

A name server configured for a large number of zones (hundreds or more) needs enough file descriptors
available for zone transfers and zone file updates, which default OS settings often don't provide.
It's necessary to check with the OS configuration and documentation and ensure the number of file
descriptors (sometimes called a number of concurrently open files) effective for the knotd process
is set suitably high. The number of concurrently open incoming TCP connections must be taken into
account too. In other words, the required setting is affected by the :ref:`server_tcp-max-clients`
setting.

Sysctl and NIC optimizations
----------------------------

There are several recommendations based on Knot developers' experience with their specific HW and SW
(mainstream Intel-based servers, Debian-based GNU/Linux distribution). They may improve or impact
performance in common use cases.

If your NIC driver allows it (see /proc/interrupts for hint), set CPU affinity (/proc/irq/$IRQ/smp_affinity)
manually so that each NIC channel is served by unique CPU core(s). You must turn off irqbalance service
in advance to avoid configuration override.

Configure sysctl as follows: ::

    socket_bufsize=1048576
    busy_latency=0
    backlog=40000
    optmem_max=20480

    net.core.wmem_max     = $socket_bufsize
    net.core.wmem_default = $socket_bufsize
    net.core.rmem_max     = $socket_bufsize
    net.core.rmem_default = $socket_bufsize
    net.core.busy_read = $busy_latency
    net.core.busy_poll = $busy_latency
    net.core.netdev_max_backlog = $backlog
    net.core.optmem_max = $optmem_max

Disable huge pages.

Configure your CPU to "performance" mode. This can be achieved depending on architecture, e.g. in BIOS,
or e.g. configuring /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor to "performance".

Tune your NIC device with ethtool: ::

    ethtool -A $dev autoneg off rx off tx off
    ethtool -K $dev tso off gro off ufo off
    ethtool -G $dev rx 4096 tx 4096
    ethtool -C $dev rx-usecs 75
    ethtool -C $dev tx-usecs 75
    ethtool -N $dev rx-flow-hash udp4 sdfn
    ethtool -N $dev rx-flow-hash udp6 sdfn

On FreeBSD you can just: ::

    ifconfig ${dev} -rxcsum -txcsum -lro -tso

Knot developers are open to hear about users' further suggestions about network devices tuning/optimization.
