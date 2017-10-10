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
The ``default`` template identifier is reserved for the default template::

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

Access control list (ACL)
=========================

An ACL list specifies which remotes are allowed to send the server a specific
request. A remote can be a single IP address or a network subnet. Also a TSIG
key can be assigned (see :doc:`keymgr <man_keymgr>` how to generate a TSIG key).

With no ACL rule, all the actions are denied for the zone. Each ACL rule
can allow one or more actions for given address/subnet/TSIG, or deny them.

The rule precendence, if multiple rules match (e.g. overlapping address ranges),
is not for stricter or more specific rules. In any case, just the first -- in the
order of rules in zone or template acl configuration item, not in the order of
declarations in acl section -- matching rule applies and the rest is ignored.

See following examples and :ref:`ACL section`.::

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
        acl: [deny_rule, address_rule] # deny_rule first here to take precendence

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

Note that a slave zone may serve as a master zone at the same time::

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

.. _dnssec:

Automatic DNSSEC signing
========================

Knot DNS supports automatic DNSSEC signing for static zones. The signing
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
  existing keys must be imported using ``keymgr import-bind`` command
  before enabling the automatic signing. Also the algorithm in the policy must
  match the algorithm of all imported keys. Otherwise the zone will be re-signed
  at all.

.. _dnssec-automatic-ksk-management:

Automatic KSK management
------------------------

For automatic KSK management, first configure ZSK management like above, and use
additional options in :ref:`policy section <Policy section>`, mostly specifying
desired (finite) lifetime for KSK: ::

  remote:
    - id: test_zone_server
      address: 192.168.12.1@53

  submission:
    - id: test_zone_sbm
      parent: [test_zone_server]

  policy:
    - id: rsa
      algorithm: RSASHA256
      ksk-size: 2048
      zsk-size: 1024
      zsk-lifetime: 30d
      ksk-lifetime: 365d
      ksk-submission: test_zone_sbm

  zone:
    - domain: myzone.test
      dnssec-signing: on
      dnssec-policy: rsa

After the initially-generated KSK reaches its lifetime, new KSK is published and after
convenience delay the submission is started. The server publishes CDS and CDNSKEY records
and the user shall propagate them to the parent. The server periodically checks for
DS at the master and when positive, finishes the rollover.

To share KSKs among zones, set the ksk-shared policy parameter. It is strongly discouraged to
change the policy ``id`` afterwards! The shared key's creation timestamp will be equal for all
zones, but other timers (e.g. activate, retire) may get out of sync. ::

  policy:
    - id: shared
      ...
      ksk-shared: true

  zone:
    - domain: firstzone.test
      dnssec-signing: on
      dnssec-policy: shared

  zone:
    - domain: secondzone.test
      dnssec-signing: on
      dnssec-policy: shared

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
Let's use the Single-Type Signing scheme with two algorithms. Run:

.. code-block:: console

  $ keymgr myzone.test. generate algorithm=ECDSAP256SHA256
  $ keymgr myzone.test. generate algorithm=ED25519

And reload the server. The zone will be signed.

To perform a manual rollover of a key, the timing parameters of the key need
to be set. Let's roll the RSA key. Generate a new RSA key, but do not activate
it yet:

.. code-block:: console

  $ keymgr myzone.test. generate algorithm=RSASHA256 size=1024 active=+1d

Take the key ID (or key tag) of the old RSA key and disable it the same time
the new key gets activated:

.. code-block:: console

  $ keymgr myzone.test. set <old_key_id> retire=+1d remove=+1d

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

On-slave signing
----------------

It is possible to enable automatic DNSSEC zone signing even on a slave
server. If enabled, the zone is signed after every AXFR/IXFR transfer
from master, so that the slave always serves a signed up-to-date version
of the zone.

It is strongly recommended to block any outside access to the master
server, so that only the slave's signed version of the zone is served.

Enabled on-slave signing introduces events when the slave zone changes
while the master zone remains unchanged, such as a key rollover or
refreshing of RRSIG records, which cause inequality of zone SOA serial
between master and slave. The slave server handles this by saving the
master's SOA serial in a special variable inside KASP DB and appropriately
modifiying AXFR/IXFR queries/answers to keep the communication with
master consistent while applying the changes with a different serial.

It is recommended to use UNIX time serial policy on master and incremental
serial policy on slave so that their SOA serials are equal most of the time.

.. _dnssec-limitations:

Limitations
-----------

The current DNSSEC automatic key management in Knot DNS has some limitations:

- Only one DNSSEC algorithm can be used per zone.
- ZSK rollover always uses key pre-publish method.
- KSK rollover always uses pre-publish double-ksk method.

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

      mod-synthrecord, mod-onlinesign, mod-rrl, mod-dnstap, mod-stats

Performance Tuning
==================

Numbers of Workers
------------------

There are three types of workers ready for parallel execution of performance-oriented tasks:
UDP workers, TCP workers, and Background workers. The first two types handle all network requests
coming through UDP and TCP protocol (respectively) and do all the response job for common
queries. Background workers process changes to the zone.

By default, Knot determines well-fitting number of workers based on the number of CPU cores.
The user can specify the numbers of workers for each type with configuration/server section:
:ref:`server_udp-workers`, :ref:`server_tcp-workers`, :ref:`server_background-workers`.

An indication on when to increase number of workers is a situation when the server is lagging behind
the expected performance, while the CPU usage is low. This is usually because of waiting for network
or I/O response during the operation. It may be caused by Knot design not fitting well the usecase.
The user should try increasing the number of workers (of the related type) slightly above 100 and if
the performance gets better, he can decide about further exact setting.

Sysctl and NIC optimizations
----------------------------

There are several recommendations based on Knot developers' experience with their specific HW and SW
(mainstream Intel-based servers, Debian-based GNU/Linux distribution). They may or may not positively
(or negatively) influence performance in common use cases.

If your NIC driver allows it (see /proc/interrupts for hint), set CPU affinity (/proc/irq/$IRQ/smp_affinity)
manually so that each NIC channel is served by unique CPU core(s). You must turn off irqbalance service
before to avoid configuration override.

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

