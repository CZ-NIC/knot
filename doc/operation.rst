.. highlight:: console
.. _Operation:

*********
Operation
*********

The Knot DNS server part :doc:`knotd<man_knotd>` can run either in the foreground,
or in the background using the ``-d`` option. When run in the foreground, it
doesn't create a PID file.  Other than that, there are no differences and you
can control both the same way.

The tool :doc:`knotc<man_knotc>` is designed as a user front-end, making it easier
to control a running server daemon. If you want to control the daemon directly,
use ``SIGINT`` to quit the process or ``SIGHUP`` to reload the configuration.

If you pass neither configuration file (``-c`` parameter) nor configuration
database (``-C`` parameter), the server will first attempt to use the default
configuration database stored in ``/var/lib/knot/confdb`` or the
default configuration file stored in ``/etc/knot/knot.conf``. Both the
default paths can be reconfigured with ``--with-storage=path`` or
``--with-configdir=path`` respectively.

Example of server start as a daemon::

    $ knotd -d -c knot.conf

Example of server shutdown::

    $ knotc -c knot.conf stop

For a complete list of actions refer to the program help (``-h`` parameter)
or to the corresponding manual page.

Also, the server needs to create :ref:`server_rundir` and :ref:`zone_storage`
directories in order to run properly.

.. _Configuration database:

Configuration database
======================

In the case of a huge configuration file, the configuration can be stored
in a binary database. Such a database can be simply initialized::

    $ knotc conf-init

or preloaded from a file::

    $ knotc conf-import input.conf

Also the configuration database can be exported into a textual file::

    $ knotc conf-export output.conf

.. WARNING::
   The import and export commands access the configuration database
   directly, without any interaction with the server. Therefore, any data
   not yet committed to the database won't be exported. And the server won't
   reflect imported configuration correctly. So it is strictly recommended to
   import new configuration when the server is not running.

.. _Dynamic configuration:

Dynamic configuration
=====================

The configuration database can be accessed using the server control interface
while the server is running. To get the full power of the dynamic configuration,
the server must be started with a specified configuration database location
or with the default database initialized. Otherwise all the changes to the
configuration will be temporary (until the server is stopped).

.. NOTE::
   The database can be :ref:`imported<Configuration database>` in advance.

Most of the commands get an item name and value parameters. The item name is
in the form of ``section[identifier].name``. If the item is multivalued,
more values can be specified as individual (command line) arguments.

.. CAUTION::
   Beware of the possibility of pathname expansion by the shell. For this reason,
   it is advisable to escape (with backslash) square brackets or to quote command parameters if
   not executed in the interactive mode.

To get the list of configuration sections or to get the list of section items::

    $ knotc conf-list
    $ knotc conf-list 'server'

To get the whole configuration or to get the whole configuration section or
to get all section identifiers or to get a specific configuration item::

    $ knotc conf-read
    $ knotc conf-read 'remote'
    $ knotc conf-read 'zone.domain'
    $ knotc conf-read 'zone[example.com].master'

.. WARNING::
   The following operations don't work on OpenBSD!

Modifying operations require an active configuration database transaction.
Just one transaction can be active at a time. Such a transaction then can
be aborted or committed. A semantic check is executed automatically before
every commit::

    $ knotc conf-begin
    $ knotc conf-abort
    $ knotc conf-commit

To set a configuration item value or to add more values or to add a new
section identifier or to add a value to all identified sections::

    $ knotc conf-set 'server.identity' 'Knot DNS'
    $ knotc conf-set 'server.listen' '0.0.0.0@53' '::@53'
    $ knotc conf-set 'zone[example.com]'
    $ knotc conf-set 'zone.slave' 'slave2'

.. NOTE::
   Also the include operation can be performed. A non-absolute file
   location is relative to the server binary path, not to the control binary
   path!

   ::

      $ knotc conf-set 'include' '/tmp/new_zones.conf'

To unset the whole configuration or to unset the whole configuration section
or to unset an identified section or to unset an item or to unset a specific
item value::

    $ knotc conf-unset
    $ knotc conf-unset 'zone'
    $ knotc conf-unset 'zone[example.com]'
    $ knotc conf-unset 'zone[example.com].master'
    $ knotc conf-unset 'zone[example.com].master' 'remote2' 'remote5'

To get the change between the current configuration and the active transaction
for the whole configuration or for a specific section or for a specific
identified section or for a specific item::

    $ knotc conf-diff
    $ knotc conf-diff 'zone'
    $ knotc conf-diff 'zone[example.com]'
    $ knotc conf-diff 'zone[example.com].master'

.. CAUTION::
   While it is possible to change most of the configuration parameters
   dynamically or via configuration file reload, a few of the parameters
   in the section ``server`` require restarting the server, such that the changes
   take effect. These parameters are:
   :ref:`rundir<server_rundir>`,
   :ref:`user<server_user>`,
   :ref:`pidfile<server_pidfile>`,
   :ref:`tcp-reuseport<server_tcp-reuseport>`,
   :ref:`udp-workers<server_udp-workers>`,
   :ref:`tcp-workers<server_tcp-workers>`,
   :ref:`background-workers<server_background-workers>`, and
   :ref:`listen<server_listen>`.

An example of possible configuration initialization::

    $ knotc conf-begin
    $ knotc conf-set 'server.listen' '0.0.0.0@53' '::@53'
    $ knotc conf-set 'remote[master_server]'
    $ knotc conf-set 'remote[master_server].address' '192.168.1.1'
    $ knotc conf-set 'template[default]'
    $ knotc conf-set 'template[default].storage' '/var/lib/knot/zones/'
    $ knotc conf-set 'template[default].master' 'master_server'
    $ knotc conf-set 'zone[example.com]'
    $ knotc conf-diff
    $ knotc conf-commit

.. _Secondary mode:

Secondary (slave) mode
======================

Running the server as a secondary server is very straightforward as you
usually bootstrap zones over AXFR and thus avoid any manual zone operations.
In contrast to AXFR, when the incremental transfer finishes, it stores
the differences in the journal file and doesn't update the zone file
immediately but after the :ref:`zone_zonefile-sync` period elapses.

.. _Primary mode:

Primary (master) mode
=====================

If you just want to check the zone files before starting, you can use::

    $ knotc zone-check example.com

.. _Editing zones:

Reading and editing zones
=========================

Knot DNS allows you to read or change zone contents online using the server
control interface.

.. WARNING::
   Avoid concurrent zone access when a zone event (zone file load, refresh,
   DNSSEC signing, dynamic update) is in progress or pending. In such a case
   zone events must be frozen before. For more information on how to freeze the
   zone read :ref:`Editing zone file`.

To get contents of all configured zones, or a specific zone contents, or zone
records with a specific owner, or even with a specific record type::

    $ knotc zone-read --
    $ knotc zone-read example.com
    $ knotc zone-read example.com ns1
    $ knotc zone-read example.com ns1 NS

.. NOTE::
   If the record owner is not a fully qualified domain name, then it is
   considered as a relative name to the zone name.

To start a writing transaction on all zones or on specific zones::

    $ knotc zone-begin --
    $ knotc zone-begin example.com example.net

Now you can list all nodes within the transaction using the ```zone-get```
command, which always returns current data with all changes included. The
command has the same syntax as ```zone-read```.

Within the transaction, you can add a record to a specific zone or to all
zones with an open transaction::

    $ knotc zone-set example.com ns1 3600 A 192.168.0.1
    $ knotc zone-set -- ns1 3600 A 192.168.0.1

To remove all records with a specific owner, or a specific rrset, or
specific record data::

    $ knotc zone-unset example.com ns1
    $ knotc zone-unset example.com ns1 A
    $ knotc zone-unset example.com ns1 A 192.168.0.2

To see the difference between the original zone and the current version::

    $ knotc zone-diff example.com

Finally, either commit or abort your transaction::

    $ knotc zone-commit example.com
    $ knotc zone-abort example.com

A full example of setting up a completely new zone from scratch::

    $ knotc conf-begin
    $ knotc conf-set zone.domain example.com
    $ knotc conf-commit
    $ knotc zone-begin example.com
    $ knotc zone-set example.com @ 7200 SOA ns hostmaster 1 86400 900 691200 3600
    $ knotc zone-set example.com ns 3600 A 192.168.0.1
    $ knotc zone-set example.com www 3600 A 192.168.0.100
    $ knotc zone-commit example.com

.. NOTE::
    If quotes are necessary for record data specification, remember to escape them::

       $ knotc zone-set example.com @ 3600 TXT \"v=spf1 a:mail.example.com -all\"

.. _Editing zone file:

Reading and editing the zone file safely
========================================

It's always possible to read and edit zone contents via zone file manipulation.
It may lead to confusion, however, if the zone contents are continuously being
changed by DDNS, DNSSEC signing and the like. In such a case, the safe way to
modify the zone file is to freeze zone events first::

    $ knotc -b zone-freeze example.com.
    $ knotc -b zone-flush example.com.

After calling freeze on the zone, there still may be running zone operations (e.g. signing),
causing freeze pending. Because of this, the blocking mode is used to ensure
the operation was finished. Then the zone can be flushed to a file.

Now the zone file can be safely modified (e.g. using a text editor).
If :ref:`zone_zonefile-load` is not set to `difference-no-serial`, it's also necessary to
**increase SOA serial** in this step to keep consistency. Finally, we can load the
modified zone file and if successful, thaw the zone::

    $ knotc -b zone-reload example.com.
    $ knotc zone-thaw example.com.

.. _Zone loading:

Zone loading
============

The process of how the server loads a zone is influenced by the configuration of the
:ref:`zonefile-load <zone_zonefile-load>` and :ref:`journal-content <zone_journal-content>`
parameters (also DNSSEC signing applies), the existence of a zone file and journal
(and their relative out-of-dateness), and whether it is a cold start of the server
or a zone reload (e.g. invoked by the :doc:`knotc<man_knotc>` interface). Please note
that zone transfers are not taken into account here – they are planned after the zone
is loaded (including AXFR bootstrap).

If the zone file exists and is not excluded by the configuration, it is first loaded
and according to its SOA serial number, relevant journal changesets are applied.
If this is a zone reload and we have :ref:`zone_zonefile-load` set to `difference`, the difference
between old and new contents is computed and stored in the journal like an update.
The zone file should be either unchanged since last load or changed with incremented
SOA serial. In the case of a decreased SOA serial, the load is interrupted with
an error; if unchanged, it is increased by the server.

If the procedure described above succeeds without errors, the resulting zone contents are (after potential DNSSEC signing)
used as the new zone.

The option :ref:`zone_journal-content` set to `all` lets the server, beside better performance, keep
track of the zone contents also across server restarts. It makes the cold start
effectively work like a zone reload with the old contents loaded from the journal
(unless this is the very first start with the zone not yet saved into the journal).

.. _Journal behaviour:

Journal behaviour
=================

The zone journal keeps some history of changes made to the zone. It is useful for
responding to IXFR queries. Also if :ref:`zone file flush <zone_zonefile-sync>` is disabled, the
journal keeps the difference between the zone file and the current zone in case of server shutdown.
The history is stored in changesets – differences of zone contents between two
(usually subsequent) zone versions (specified by SOA serials).

Journals of all zones are stored in a common LMDB database. Huge changesets are
split into 70 KiB [#fn-hc]_ blocks to prevent fragmentation of the DB. The
journal does each operation in one transaction to keep consistency of the DB and performance.

Each zone journal has its own occupation limits :ref:`maximum usage <zone_journal-max-usage>`
and :ref:`maximum depth <zone_journal-max-depth>`. Changesets are stored in the journal
one by one. When hitting any of the limits, the zone is flushed into the zone file
if there are no redundant changesets to delete, and the oldest changesets are deleted.
In the case of the size limit, twice [#fn-hc]_ the needed amount of space is purged
to prevent overly frequent deletes.

If :ref:`zone file flush <zone_zonefile-sync>` is disabled, then instead of flushing
the zone, the journal tries to save space by merging the changesets into a special one.
This approach is effective if the changes rewrite each other, e.g. periodically
changing the same zone records, re-signing the whole zone etc. Thus the difference between the zone
file and the zone is still preserved even if the journal deletes some older changesets.

If the journal is used to store both zone history and contents, a special changeset
is present with zone contents. When the journal gets full, the changes are merged into this
special changeset.

There is also a :ref:`safety hard limit <database_journal-db-max-size>` for overall
journal database size, but it's strongly recommended to set the per-zone limits in
a way to prevent hitting this one. For LMDB, it's hard to recover from the
database-full state. For wiping one zone's journal, see *knotc zone-purge +journal*
command.

.. [#fn-hc] This constant is hardcoded.

.. _Handling, zone file, journal, changes, serials:

Handling zone file, journal, changes, serials
=============================================

Some configuration options regarding the zone file and journal, together with operation
procedures, might lead to unexpected results. This chapter points out
potential interference and both recommends and warns before some combinations thereof.
Unfortunately, there is no optimal combination of configuration options,
every approach has some disadvantages.

Example 1
---------

Keep the zone file updated::

   zonefile-sync: 0
   zonefile-load: whole
   journal-content: changes

These are default values. The user can always check the current zone
contents in the zone file, and also modify it (recommended with server turned-off or
taking the :ref:`safe way<Editing zone file>`). The journal serves here just as a source of
history for secondary servers' IXFR. Some users dislike that the server overwrites their
prettily prepared zone file.

Example 2
---------

Zonefileless setup::

   zonefile-sync: -1
   zonefile-load: none
   journal-content: all

Zone contents are stored only in the journal. The zone is updated by DDNS,
zone transfer, or via the control interface. The user might have filled the
zone contents initially from a zone file by setting :ref:`zone_zonefile-load` to
`whole` temporarily.
It's also a good setup for secondary servers. Anyway, it's recommended to carefully tune
the journal-size-related options to avoid surprises like the journal getting full.

Example 3
---------

Input-only zone file::

   zonefile-sync: -1
   zonefile-load: difference
   journal-content: changes

The user can make changes to the zone by editing the zone file, and his pretty zone file
is never overwritten or filled with DNSSEC-related autogenerated records – they are
only stored in the journal.

The zone file's SOA serial must be properly set to a number which is higher than the
current SOA serial in the zone (not in the zone file) if manually updated!

Example 4
---------

Auto-increment SOA serial::

   zonefile-sync: -1
   zonefile-load: difference-no-serial
   journal-content: all

This is similar to the previous setup, but the SOA serial is handled by the server
automatically. So the user no longer needs to care about it in the zone file.

However, this requires setting :ref:`zone_journal-content` to `all` so that
the information about the last real SOA serial is preserved in case of server re-start.

.. _DNSSEC Key states:

DNSSEC key states
=================

During its lifetime, a DNSSEC key finds itself in different states. Most of the time it
is used for signing the zone and published in the zone. In order to exchange
the key, one type of a key rollover is necessary, and during this rollover,
the key goes through various states with respect to the rollover type and also the
state of the other key being rolled-over.

First, let's list the states of the key being rolled-in.

Standard states:

- ``active`` — The key is used for signing.
- ``published`` — The key is published in the zone, but not used for signing. If the key is
  a KSK or CSK, it is used for signing the DNSKEY RRSet.
- ``ready`` (only for KSK) — The key is published in the zone and used for signing. The
  old key is still active, since we are waiting for the DS records in the parent zone to be
  updated (i.e. "KSK submission").

Special states for algorithm rollover:

- ``pre-active`` — The key is not yet published in the zone, but it's used for signing the zone.
- ``published`` — The key is published in the zone, and it's still used for signing since the
  pre-active state.

Second, we list the states of the key being rolled-out.

Standard states:

- ``retire-active`` — The key is still used for signing, and is published in the zone, waiting for
  the updated DS records in parent zone to be acked by resolvers (KSK case) or synchronizing
  with KSK during algorithm rollover (ZSK case).
- ``retired`` — The key is no longer used for signing. If ZSK, the key is still published in the zone.
- ``removed`` — The key is not used in any way (in most cases such keys are deleted immediately).

Special states for algorithm rollover:

- ``post-active`` — The key is no longer published in the zone, but still used for signing.

Special states for :rfc:`5011` trust anchor roll-over

- ``revoke`` (only for KSK) — The key is published and used for signing, and the Revoked flag is set.

.. NOTE::
   Trust anchor roll-over is not implemented with automatic key management.

   The ``revoke`` state can only be established using :doc:`keymgr<man_keymgr>` when using
   :ref:`dnssec-manual-key-management`.

The states listed above are relevant for :doc:`keymgr<man_keymgr>` operations like generating
a key, setting its timers and listing KASP database.

Note that the key "states" displayed in the server log lines while zone signing
are not according to those listed above, but just a hint as to what the key is currently used for
(e.g. "public, active" = key is published in the zone and used for signing).

.. _DNSSEC Key rollovers:

DNSSEC key rollovers
====================

This section describes the process of DNSSEC key rollover and its implementation
in Knot DNS, and how the operator might watch and check that it's working correctly.
The prerequisite is automatic zone signing with enabled
:ref:`automatic key management<dnssec-automatic-ksk-management>`.

The KSK and ZSK rollovers are triggered by the respective zone key getting old according
to the settings (see :ref:`KSK<policy_ksk-lifetime>` and :ref:`ZSK<policy_zsk-lifetime>` lifetimes).

The algorithm rollover starts when the policy :ref:`algorithm<policy_algorithm>`
field is updated to a different value.

The signing scheme rollover happens when the policy :ref:`signing scheme<policy_single-type-signing>`
field is changed.

It's also possible to change the algorithm and signing scheme in one rollover.

The operator may check the next rollover phase time by watching the next zone signing time,
either in the log or via ``knotc zone-status``. There is no special log for finishing a rollover.

.. NOTE::
   There are never two key rollovers running in parallel for one zone. If
   a rollover is triggered while another is in progress, it waits until the
   first one is finished.

The ZSK rollover is performed with Pre-publish method, KSK rollover uses Double-Signature
scheme, as described in :rfc:`6781`.

.. _Automatic KSK and ZSK rollovers example:

Automatic KSK and ZSK rollovers example
---------------------------------------

Let's start with the following set of keys::

  2021-05-10T20:50:00+0200 info: [example.com.] DNSSEC, key, tag 50613, algorithm ECDSAP256SHA256, KSK, public, active
  2021-05-10T20:50:00+0200 info: [example.com.] DNSSEC, key, tag 62932, algorithm ECDSAP256SHA256, public, active

The last fields hint the key state: ``public`` denotes a key that will be presented
as the DNSKEY record, ``ready`` means that CDS/CDNSKEY records were created,
``active`` tells us that the key is used for signing, while ``active+`` is an
active key undergoing a roll-over or roll-in.

For demonstration purposes, the following configuration is used::

  submission:
   - id: test_submission
     check-interval: 2s
     parent: dnssec_validating_resolver

  policy:
   - id: test_policy
     ksk-lifetime: 5m
     zsk-lifetime: 2m
     propagation-delay: 2s
     dnskey-ttl: 10s
     zone-max-ttl: 15s
     ksk-submission: test_submission

Upon the zone's KSK lifetime expiration, a new KSK is generated and the rollover
continues along the lines of :rfc:`6781#section-4.1.2`::

  # KSK Rollover (50613 -> 9081)

  2021-05-10T20:50:00+0200 info: [example.com.] DNSSEC, signing zone
  2021-05-10T20:50:00+0200 info: [example.com.] DNSSEC, KSK rollover started
  2021-05-10T20:50:00+0200 info: [example.com.] DNSSEC, key, tag 50613, algorithm ECDSAP256SHA256, KSK, public, active
  2021-05-10T20:50:00+0200 info: [example.com.] DNSSEC, key, tag  9081, algorithm ECDSAP256SHA256, KSK, public, active+
  2021-05-10T20:50:00+0200 info: [example.com.] DNSSEC, key, tag 62932, algorithm ECDSAP256SHA256, public, active
  2021-05-10T20:50:00+0200 info: [example.com.] DNSSEC, signing started
  2021-05-10T20:50:00+0200 info: [example.com.] DNSSEC, successfully signed
  2021-05-10T20:50:00+0200 info: [example.com.] DNSSEC, next signing at 2021-05-10T20:50:12+0200

  ... (propagation-delay + dnskey-ttl) ...

  2021-05-10T20:50:12+0200 info: [example.com.] DNSSEC, signing zone
  2021-05-10T20:50:12+0200 notice: [example.com.] DNSSEC, KSK submission, waiting for confirmation
  2021-05-10T20:50:12+0200 info: [example.com.] DNSSEC, key, tag 50613, algorithm ECDSAP256SHA256, KSK, public, active
  2021-05-10T20:50:12+0200 info: [example.com.] DNSSEC, key, tag  9081, algorithm ECDSAP256SHA256, KSK, public, ready, active+
  2021-05-10T20:50:12+0200 info: [example.com.] DNSSEC, key, tag 62932, algorithm ECDSAP256SHA256, public, active
  2021-05-10T20:50:12+0200 info: [example.com.] DNSSEC, signing started
  2021-05-10T20:50:12+0200 info: [example.com.] DNSSEC, successfully signed
  2021-05-10T20:50:12+0200 info: [example.com.] DNSSEC, next signing at 2021-05-17T20:49:56+0200

At this point the new KSK has to be submitted to the parent zone. Knot detects the updated parent's DS
record automatically (and waits for additional period of the DS's TTL before retiring the old key)
if :ref:`parent DS check<Submission section>` is configured, otherwise the
operator must confirm it manually (using ``knotc zone-ksk-submitted``)::

  2021-05-10T20:50:12+0200 info: [example.com.] DS check, outgoing, remote 127.0.0.1@5300, KSK submission check: negative
  2021-05-10T20:50:14+0200 info: [example.com.] DS check, outgoing, remote 127.0.0.1@5300, KSK submission check: negative
  2021-05-10T20:50:16+0200 info: [example.com.] DS check, outgoing, remote 127.0.0.1@5300, KSK submission check: positive
  2021-05-10T20:50:16+0200 notice: [example.com.] DNSSEC, KSK submission, confirmed
  2021-05-10T20:50:16+0200 info: [example.com.] DNSSEC, signing zone
  2021-05-10T20:50:16+0200 info: [example.com.] DNSSEC, key, tag  9081, algorithm ECDSAP256SHA256, KSK, public, active
  2021-05-10T20:50:16+0200 info: [example.com.] DNSSEC, key, tag 50613, algorithm ECDSAP256SHA256, KSK, public, active+
  2021-05-10T20:50:16+0200 info: [example.com.] DNSSEC, key, tag 62932, algorithm ECDSAP256SHA256, public, active
  2021-05-10T20:50:16+0200 info: [example.com.] DNSSEC, signing started
  2021-05-10T20:50:16+0200 info: [example.com.] DNSSEC, successfully signed
  2021-05-10T20:50:16+0200 info: [example.com.] DNSSEC, next signing at 2021-05-10T20:50:23+0200

  ... (parent's DS TTL is 7 seconds) ...

  2021-05-10T20:50:23+0200 info: [example.com.] DNSSEC, signing zone
  2021-05-10T20:50:23+0200 info: [example.com.] DNSSEC, key, tag  9081, algorithm ECDSAP256SHA256, KSK, public, active
  2021-05-10T20:50:23+0200 info: [example.com.] DNSSEC, key, tag 62932, algorithm ECDSAP256SHA256, public, active
  2021-05-10T20:50:23+0200 info: [example.com.] DNSSEC, signing started
  2021-05-10T20:50:23+0200 info: [example.com.] DNSSEC, successfully signed
  2021-05-10T20:50:23+0200 info: [example.com.] DNSSEC, next signing at 2021-05-10T20:51:56+0200

Upon the zone's ZSK lifetime expiration, a new ZSK is generated and the rollover
continues along the lines of :rfc:`6781#section-4.1.1`::

  # ZSK Rollover (62932 -> 33255)

  2021-05-10T20:51:56+0200 info: [example.com.] DNSSEC, signing zone
  2021-05-10T20:51:56+0200 info: [example.com.] DNSSEC, ZSK rollover started
  2021-05-10T20:51:56+0200 info: [example.com.] DNSSEC, key, tag  9081, algorithm ECDSAP256SHA256, KSK, public, active
  2021-05-10T20:51:56+0200 info: [example.com.] DNSSEC, key, tag 33255, algorithm ECDSAP256SHA256, public
  2021-05-10T20:51:56+0200 info: [example.com.] DNSSEC, key, tag 62932, algorithm ECDSAP256SHA256, public, active
  2021-05-10T20:51:56+0200 info: [example.com.] DNSSEC, signing started
  2021-05-10T20:51:56+0200 info: [example.com.] DNSSEC, successfully signed
  2021-05-10T20:51:56+0200 info: [example.com.] DNSSEC, next signing at 2021-05-10T20:52:08+0200

  ... (propagation-delay + dnskey-ttl) ...

  2021-05-10T20:52:08+0200 info: [example.com.] DNSSEC, signing zone
  2021-05-10T20:52:08+0200 info: [example.com.] DNSSEC, key, tag  9081, algorithm ECDSAP256SHA256, KSK, public, active
  2021-05-10T20:52:08+0200 info: [example.com.] DNSSEC, key, tag 62932, algorithm ECDSAP256SHA256, public
  2021-05-10T20:52:08+0200 info: [example.com.] DNSSEC, key, tag 33255, algorithm ECDSAP256SHA256, public, active
  2021-05-10T20:52:08+0200 info: [example.com.] DNSSEC, signing started
  2021-05-10T20:52:08+0200 info: [example.com.] DNSSEC, successfully signed
  2021-05-10T20:52:08+0200 info: [example.com.] DNSSEC, next signing at 2021-05-10T20:52:25+0200

  ... (propagation-delay + zone-max-ttl) ...

  2021-05-10T20:52:25+0200 info: [example.com.] DNSSEC, signing zone
  2021-05-10T20:52:25+0200 info: [example.com.] DNSSEC, key, tag  9081, algorithm ECDSAP256SHA256, KSK, public, active
  2021-05-10T20:52:25+0200 info: [example.com.] DNSSEC, key, tag 33255, algorithm ECDSAP256SHA256, public, active
  2021-05-10T20:52:25+0200 info: [example.com.] DNSSEC, signing started
  2021-05-10T20:52:25+0200 info: [example.com.] DNSSEC, successfully signed
  2021-05-10T20:52:25+0200 info: [example.com.] DNSSEC, next signing at 2021-05-10T20:54:08+0200
  2021-05-10T20:54:08+0200 info: [example.com.] DNSSEC, signing zone

Further rollovers::

  ... (zsk-lifetime - propagation-delay - zone-max-ttl) ...

  # Another ZSK Rollover (33255 -> 49526)

  2021-05-10T20:54:08+0200 info: [example.com.] DNSSEC, signing zone
  2021-05-10T20:54:08+0200 info: [example.com.] DNSSEC, ZSK rollover started
  2021-05-10T20:54:08+0200 info: [example.com.] DNSSEC, key, tag  9081, algorithm ECDSAP256SHA256, KSK, public, active
  2021-05-10T20:54:08+0200 info: [example.com.] DNSSEC, key, tag 49526, algorithm ECDSAP256SHA256, public
  2021-05-10T20:54:08+0200 info: [example.com.] DNSSEC, key, tag 33255, algorithm ECDSAP256SHA256, public, active
  2021-05-10T20:54:08+0200 info: [example.com.] DNSSEC, signing started
  2021-05-10T20:54:08+0200 info: [example.com.] DNSSEC, successfully signed
  2021-05-10T20:54:08+0200 info: [example.com.] DNSSEC, next signing at 2021-05-10T20:54:20+0200

  ...

  # Another KSK Rollover (9081 -> 9179)

  2021-05-10T20:55:00+0200 info: [example.com.] DNSSEC, signing zone
  2021-05-10T20:55:00+0200 info: [example.com.] DNSSEC, KSK rollover started
  2021-05-10T20:55:00+0200 info: [example.com.] DNSSEC, key, tag  9081, algorithm ECDSAP256SHA256, KSK, public, active
  2021-05-10T20:55:00+0200 info: [example.com.] DNSSEC, key, tag  9179, algorithm ECDSAP256SHA256, KSK, public, active+
  2021-05-10T20:55:00+0200 info: [example.com.] DNSSEC, key, tag 49526, algorithm ECDSAP256SHA256, public, active
  2021-05-10T20:55:00+0200 info: [example.com.] DNSSEC, signing started
  2021-05-10T20:55:00+0200 info: [example.com.] DNSSEC, successfully signed
  2021-05-10T20:55:00+0200 info: [example.com.] DNSSEC, next signing at 2021-05-10T20:55:12+0200

  ...

.. TIP::
   If systemd is available, the KSK submission event is logged into journald
   in a structured way. The intended use case is to trigger a user-created script.
   Example::

     journalctl -f -t knotd -o json | python3 -c '
     import json, sys
     for line in sys.stdin:
       k = json.loads(line);
       if "KEY_SUBMISSION" in k:
         print("%s, zone=%s, keytag=%s" % (k["__REALTIME_TIMESTAMP"], k["ZONE"], k["KEY_SUBMISSION"]))
     '

.. _DNSSEC Shared KSK:

DNSSEC shared KSK
=================

Knot DNS allows, with automatic DNSSEC key management, to configure a shared KSK for multiple zones.
By enabling :ref:`policy_ksk-shared`, we tell Knot to share all newly-created KSKs
among all the zones with the same :ref:`DNSSEC signing policy<Policy section>` assigned.

The feature works as follows. Each zone still manages its keys separately. If a new KSK shall be
generated for the zone, it first checks if it can grab another zone's shared KSK instead -
that is the last generated KSK in any of the zones with the same policy assigned.
Anyway, only the cryptographic material is shared, the key may have different timers
in each zone.

.. rubric:: Consequences:

If we have an initial setting with brand new zones without any DNSSEC keys,
the initial keys for all zones are generated. With shared KSK, they will all have the same KSK,
but different ZSKs. The KSK rollovers may take place at slightly different times for each of the zones,
but the resulting new KSK will be shared again among all of them.

If we have zones which already have their keys, turning on the shared KSK feature triggers no action.
But when a KSK rollover takes place, they will use the same new key afterwards.

.. WARNING::
   Changing the policy :ref:`id<policy_id>` must be done carefully if shared
   KSK is in use.

.. _DNSSEC Delete algorithm:

DNSSEC delete algorithm
=======================

This is how to "disconnect" a signed zone from a DNSSEC-aware parent zone.
More precisely, we tell the parent zone to remove our zone's DS record by
publishing a special formatted CDNSKEY and CDS record. This is mostly useful
if we want to turn off DNSSEC on our zone so it becomes insecure, but not bogus.

With automatic DNSSEC signing and key management by Knot, this is as easy as
configuring :ref:`policy_cds-cdnskey-publish` option and reloading the configuration.
We check if the special CDNSKEY and CDS records with the rdata "0 3 0 AA==" and "0 0 0 00",
respectively, appeared in the zone.

After the parent zone notices and reflects the change, we wait for TTL expire
(so all resolvers' caches get updated), and finally we may do anything with the
zone, e.g. turning off DNSSEC, removing all the keys and signatures as desired.

.. _DNSSEC Offline KSK:

DNSSEC Offline KSK
==================

Knot DNS allows a special mode of operation where the private part of the Key Signing Key is
not available to the daemon, but it is rather stored securely in an offline storage. This requires
that the KSK/ZSK signing scheme is used (i.e. :ref:`policy_single-type-signing` is off).
The Zone Signing Key is always fully available to the daemon in order to sign common changes to the zone contents.

The server (or the "ZSK side") only uses ZSK to sign zone contents and its changes. Before
performing a ZSK rollover, the DNSKEY records will be pre-generated and signed by the
signer (the "KSK side"). Both sides exchange keys in the form of human-readable messages with the help
of the :doc:`keymgr<man_keymgr>` utility.

Pre-requisites
--------------

For the ZSK side (i.e. the operator of the DNS server), the zone has to be configured with:

- Enabled :ref:`DNSSEC signing <zone_dnssec-signing>`
- Properly configured and assigned :ref:`DNSSEC policy <Policy section>`:

  - Enabled :ref:`policy_manual`
  - Enabled :ref:`policy_offline-ksk`
  - Explicit :ref:`policy_dnskey-ttl`
  - Explicit :ref:`policy_zone-max-ttl`
  - Other options are optional
- KASP DB may contain a ZSK (the present or some previous ones)

For the KSK side (i.e. the operator of the KSK signer), the zone has to be configured with:

- Properly configured and assigned :ref:`DNSSEC policy <Policy section>`:

  - Enabled :ref:`policy_manual`
  - Enabled :ref:`policy_offline-ksk`
  - Optional :ref:`policy_rrsig-lifetime`, :ref:`policy_rrsig-refresh`,
    :ref:`policy_algorithm`, and :ref:`policy_reproducible-signing`
  - Other options are ignored
- KASP DB contains a KSK (the present or a newly generated one)

Generating and signing future ZSKs
----------------------------------

1.  Use the ``keymgr pregenerate`` command on the ZSK side to prepare the ZSKs for a specified period of time in the future. The following example
    generates ZSKs for the *example.com* zone for 6 months ahead starting from now::

     $ keymgr -c /path/to/ZSK/side.conf example.com. pregenerate +6mo

    If the time period is selected as e.g. *2 x* :ref:`policy_zsk-lifetime` *+ 4 x* :ref:`policy_propagation-delay`, it will
    prepare roughly two complete future key rollovers. The newly-generated
    ZSKs remain in non-published state until their rollover starts, i.e. the time
    they would be generated in case of automatic key management.

2.  Use the ``keymgr generate-ksr`` command on the ZSK side to export the public parts of the future ZSKs in a form
    similar to DNSKEY records. You might use the same time period as in the first step::

     $ keymgr -c /path/to/ZSK/side.conf example.com. generate-ksr +0 +6mo > /path/to/ksr/file

    Save the output of the command (called the Key Signing Request or KSR) to a file and transfer it to the KSK side e.g. via e-mail.

3.  Use the ``keymgr sign-ksr`` command on the KSK side with the KSR file from the previous step as a parameter::

     $ keymgr -c /path/to/KSK/side.conf example.com. sign-ksr /path/to/ksr/file > /path/to/skr/file

    This creates all the future forms of the DNSKEY, CDNSKEY and CSK records and all the respective RRSIGs and prints them on output. Save
    the output of the command (called the Signed Key Response or SKR) to a file and transfer it back to the ZSK side.

4.  Use the ``keymgr import-skr`` command to import the records and signatures from the SKR file generated in the last step
    into the KASP DB on the ZSK side::

     $ keymgr -c /path/to/ZSK/side.conf example.com. import-skr /path/to/skr/file

5. Use the ``knotc zone-keys-load`` command to trigger a zone re-sign on the ZSK-side and set up the future re-signing events correctly.::

    $ knotc -c /path/to/ZSK/side.conf zone-keys-load example.com.

6. Now the future ZSKs and DNSKEY records with signatures are ready in KASP DB for later usage.
   Knot automatically uses them at the correct time intervals.
   The entire procedure must be repeated before the time period selected at the beginning passes,
   or whenever a configuration is changed significantly. Importing new SKR over some previously-imported
   one leads to deleting the old offline records.

Offline KSK and manual ZSK management
-------------------------------------

If the automatically preplanned ZSK roll-overs (first step) are not desired, just set the :ref:`policy_zsk-lifetime`
to zero, and manually pregenerate ZSK keys and set their timers. Then follow the steps
``generate-ksr — sign-ksr — import-skr — zone-keys-load`` and repeat the ceremony when necessary.

Offline KSK roll-over
---------------------

The KSKs (on the KSK side) must be managed manually, but manual KSK roll-over is possible. Just plan the steps
of the KSK roll-over in advance, and whenever the KSK set or timers are changed, re-perform the relevant rest of the ceremony
``sign-ksr — import-skr — zone-keys-load``.

Emergency SKR
-------------

A general recommendation for large deployments is to have some backup pre-published keys, so that if the current ones are
compromised, they can be rolled-over to the backup ones without any delay. But in the case of Offline KSK, according to
the procedures above, both ZSK and KSK immediate rollovers require the KSR-SKR ceremony.

However, a trick can be done to achieve really immediate key substitution. This is no longer about Knot DNS functionality,
just a hint for the operator.

The idea is to perform every KSR-SKR ceremony twice: once with normal state of the keys (the backup key is only published),
and once with the keys already exchanged (the backup key is temporarily marked as active and the standard key temporarily
as public only). The second (backup) SKR should be saved for emergency key replacement.

Summary of the steps:

* Prepare KSK and ZSK side as usual, including public-only emergency key
* Perform normal Offline KSK ceremony:

  * Pre-generate ZSKs (only in the case of automatic ZSK management)
  * Generate KSR
  * Sign KSR on the KSK side
  * Import SKR
  * Re-sign the zone

* Freeze the zone on the ZSK side
* Temporarily set the backup key as active and the normal key as publish-only
* Perform backup Offline KSK ceremony:

  * Generate KSR (only if the backup key is a replacement for ZSK)
  * Sign the KSR on the KSK side
  * Save the SKR to a backup storage, don't import it yet

* Return the keys to the previous state
* Thaw the zone on the ZSK side

Emergency key replacement:

* Import the backup SKR
* Align the keys with the new states (backup key as active, compromised key as public)
* Re-sign the zone

.. _DNSSEC Import of keys to HSM:

Import of keys to HSM
=====================

Knot DNS stores DNSSEC keys in textual PEM format (:rfc:`7468`),
while many HSM management software require the keys for import to be in binary
DER format (`Rec. ITU-T X.690 <https://www.itu.int/ITU-T/recommendations/rec.aspx?rec=x.690>`_).
Keys can be converted from one format to another by software tools such as
``certtool`` from `GnuTLS <https://www.gnutls.org/>`_ suite or
``openssl`` from `OpenSSL <https://www.openssl.org/>`_ suite.

In the examples below, ``c4eae5dea3ee8c15395680085c515f2ad41941b6`` is used as the key ID,
``c4eae5dea3ee8c15395680085c515f2ad41941b6.pem`` represents the filename of the key in PEM format
as copied from the Knot DNS zone's :ref:`KASP database directory <database_kasp-db>`,
``c4eae5dea3ee8c15395680085c515f2ad41941b6.priv.der`` represents the file containing the private
key in DER format as generated by the conversion tool, and
``c4eae5dea3ee8c15395680085c515f2ad41941b6.pub.der`` represents the file containing the public
key in DER format as generated by the conversion tool.

.. code-block:: console

   $ certtool -V -k --outder --infile c4eae5dea3ee8c15395680085c515f2ad41941b6.pem \
     --outfile c4eae5dea3ee8c15395680085c515f2ad41941b6.priv.der

   $ certtool -V --pubkey-info --outder --load-privkey c4eae5dea3ee8c15395680085c515f2ad41941b6.pem \
     --outfile c4eae5dea3ee8c15395680085c515f2ad41941b6.pub.der

As an alternative, ``openssl`` can be used instead. It is necessary to specify either ``rsa`` or ``ec``
command according to the algorithm used by the key.

.. code-block:: console

   $ openssl rsa -outform DER -in c4eae5dea3ee8c15395680085c515f2ad41941b6.pem \
     -out c4eae5dea3ee8c15395680085c515f2ad41941b6.priv.der

   $ openssl rsa -outform DER -in c4eae5dea3ee8c15395680085c515f2ad41941b6.pem \
     -out c4eae5dea3ee8c15395680085c515f2ad41941b6.pub.der -pubout

Actual import of keys (both public and private keys from the same key pair) to an HSM can be done
via PKCS #11 interface, by ``pkcs11-tool`` from `OpenSC <https://github.com/OpenSC/OpenSC/wiki>`_ toolkit
for example.  In the example below, ``/usr/local/lib/pkcs11.so`` is used as a name of the PKCS #11 library
or module used for communication with the HSM.

.. code-block:: console

   $ pkcs11-tool --module /usr/local/lib/pkcs11.so --login \
     --write-object c4eae5dea3ee8c15395680085c515f2ad41941b6.priv.der --type privkey \
     --usage-sign --id c4eae5dea3ee8c15395680085c515f2ad41941b6

   $ pkcs11-tool --module /usr/local/lib/pkcs11.so -login \
     --write-object c4eae5dea3ee8c15395680085c515f2ad41941b6.pub.der --type pubkey \
     --usage-sign --id c4eae5dea3ee8c15395680085c515f2ad41941b6

.. _Controlling a running daemon:

Daemon controls
===============

Knot DNS was designed to allow server reconfiguration on-the-fly
without interrupting its operation. Thus it is possible to change
both configuration and zone files and also add or remove zones without
restarting the server. This can be done with::

    $ knotc reload

If you want to refresh the secondary zones, you can do this with::

    $ knotc zone-refresh

.. _Data and metadata backup:

Data and metadata backup
========================

Some of the zone-related data, such as zone contents or DNSSEC signing keys,
and metadata, like zone timers, might be worth backing up. For the sake of
consistency, it's usually necessary to shut down the server, or at least freeze all
the zones, before copying the data like zone files, KASP database, etc, to
a backup location. To avoid this necessity, Knot DNS provides a feature to
back up some or all of the zones seamlessly.

Online backup
-------------

While the server is running and the zones normally loaded (even when they are
constantly/frequently being updated), the user can manually trigger the
backup by calling::

    $ knotc zone-backup +backupdir /path/of/backup

To back up just some of the zones (instead of all), the user might provide
their list::

    $ knotc zone-backup +backupdir /path/to/backup zone1.com. zone2.com. ...

The backup directory should be empty or non-existing and it must be accessible
and writable for the :ref:`server_user` account under which knotd is running.
The backup procedure will begin soon and will happen zone-by-zone
(partially in parallel if more :ref:`server_background-workers` are configured).
**The user shall check the logs for the outcome of each zone's backup attempt.**
The knotc's ``-b`` parameter might be used if the user desires to wait until
the backup work is done and a simple result status is printed out.

.. TIP::
   There is a plain ASCII text file in the backup directory,
   ``knot_backup.label``, that contains some useful information about the
   backup, such as the backup creation date & time, the server identity, etc.
   Care must always be taken **not to remove this file** from the backup nor to
   damage it.

Offline restore
---------------

If the Online backup was performed for all zones, it's possible to
restore the backed up data by simply copying them to their normal locations,
since they're simply copies. For example, the user can copy (overwrite)
the backed up KASP database files to their configured location.

This restore of course must be done when the server is stopped. After starting up
the server, it should run in the same state as at the time of backup.

This method is recommended in the case of complete data loss, for example
physical server failure.

.. NOTE::
   The online backup procedure stores all zone files in a single directory
   using their default file names. If the original directory layout was
   different, then the required directory structure must be created manually
   for offline restore and zone files must be placed individually to their
   respective directories. If the zone file names don't follow the default
   pattern, they must be renamed manually to match the configuration. These
   limitations don't apply to the online restore procedure.

Online restore
--------------

This procedure is symmetrical to Online backup. By calling::

    $ knotc zone-restore +backupdir /path/of/backup

the user triggers a one-by-one zone restore from the backup on a running
server. Again, a subset of zones might be specified. It must be specified
if the backup was created for only a subset of zones.

.. NOTE::
   For restore of backups that have been created by Knot DNS releases prior
   to 3.1, it's necessary to use the ``-f`` option. Since this option also
   turns off some verification checks, it shouldn't be used in other cases.

Limitations
-----------

Neither configuration file nor :ref:`Configuration database` is backed up
by zone backup. The configuration has to be synchronized before zone restore
is performed!

If the private keys are stored in a HSM (anything using a PKCS#11 interface),
they are not backed up. This includes internal metadata of the PKCS#11 provider
software, such as key mappings, authentication information, and the configuration
of the provider. Details are vendor-specific.

The restore procedure does not care for keys deleted after taking the snapshot.
Thus, after restore, there might remain some redundant ``.pem`` files
of obsolete signing keys.

.. TIP::
   In order to seamlessly deploy a restored backup of KASP DB with respect to
   a possibly ongoing DNSSEC key rollover, it's recommended to set
   :ref:`propagation-delay <policy_propagation-delay>` to the sum of:

   - The maximum delay between beginning of the zone signing and publishing
     re-signed zone on all public secondary servers.
   - How long it takes for the backup server to start up with the restored data.
   - The period between taking backup snapshots of the live environment.

.. _Statistics:

Statistics
==========

The server provides some general statistics and optional query module statistics
(see :ref:`mod-stats<mod-stats>`).

Server statistics or global module statistics can be shown by::

    $ knotc stats
    $ knotc stats server             # Show all server counters
    $ knotc stats mod-stats          # Show all mod-stats counters
    $ knotc stats server.zone-count  # Show specific server counter

Per zone statistics can be shown by::

    $ knotc zone-stats example.com mod-stats

To show all supported counters even with 0 value, use the force option.

A simple periodic statistic dump to a YAML file can also be enabled. See
:ref:`statistics_section` for the configuration details.

As the statistics data can be accessed over the server control socket,
it is possible to create an arbitrary script (Python is supported at the moment)
which could, for example, publish the data in JSON format via HTTP(S)
or upload the data to a more efficient time series database. Take a look into
the python folder of the project for these scripts.

.. _Mode XDP:

Mode XDP
========

Thanks to recent Linux kernel capabilities, namely eXpress Data Path and AF_XDP
address family, Knot DNS offers a high-performance DNS over UDP packet processing
mode. The basic idea is to filter DNS messages close to the network device and
effectively forward them to the nameserver without touching the network stack
of the operating system. Other messages (including DNS over TCP) are processed
as usual.

If :ref:`xdp_listen` is configured, the server creates
additional XDP workers, listening on specified interface(s) and port(s) for DNS
over UDP queries. Each XDP worker handles one RX and TX network queue pair.

.. _Mode XDP_pre-requisites:

Pre-requisites
--------------

* Linux kernel 4.18+ (5.x+ is recommended for optimal performance) compiled with
  the `CONFIG_XDP_SOCKETS=y` option. The XDP mode isn't supported in other operating systems.
* A multiqueue network card, which offers enough Combined RX/TX channels, with
  native XDP support is highly recommended. Successfully tested cards:

  * Intel series 700 (driver `i40e`), maximum number of channels per interface is 64.
  * Intel series 500 (driver `ixgbe`), maximum number of channels per interface is 64.
    The number of CPUs available has to be at most 64!

* If the `knotd` service is not directly executed in the privileged mode, some
  additional Linux capabilities have to be set:

  Execute command::

    systemctl edit knot

  And insert these lines::

    [Service]
    CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_RESOURCE
    AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_RESOURCE

  The `CAP_SYS_RESOURCE` is needed on Linux < 5.11.

Optimizations
-------------

Some helpful commands::

 ethtool -N <interface> rx-flow-hash udp4 sdfn
 ethtool -N <interface> rx-flow-hash udp6 sdfn
 ethtool -L <interface> combined <?>
 ethtool -G <interface> rx <?> tx <?>
 renice -n 19 -p $(pgrep '^ksoftirqd/[0-9]*$')

Limitations
-----------

* VLAN segmentation is not supported.
* Dynamic DNS over XDP is not supported.
* MTU higher than 1792 bytes is not supported.
* Multiple BPF filters per one network device are not supported.
* Systems with big-endian byte ordering require special recompilation of the nameserver.
* IPv4 header and UDP checksums are not verified on received DNS messages.
* DNS over XDP traffic is not visible to common system tools (e.g. firewall, tcpdump etc.).
* BPF filter is not automatically unloaded from the network device. Manual filter unload::

   ip link set dev <ETH> xdp off
