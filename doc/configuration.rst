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

.. _dnssec-keyusage:

DNSSEC keys used by multiple zones 
----------------------------------

Using same key for multiple zones with automatic key management is possible. 
However, all zones must be listed in keyusage (keys directory) or they will be deleted,
when they retire in any zone.

If keys are added manually as published, but not active (for next rollover event), they are added automatically.

