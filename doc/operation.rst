.. highlight:: console
.. _Operation:

*********
Operation
*********

The Knot DNS server part ``knotd`` can run either in the foreground, or in the background
using the ``-d`` option. When run in the foreground, it doesn't create a PID file.
Other than that, there are no differences and you can control both the same way.

The tool ``knotc`` is designed as a user front-end, making it easier to control running
server daemon. If you want to control the daemon directly, use ``SIGINT`` to quit
the process or ``SIGHUP`` to reload the configuration.

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
   directly, without any interaction with the server. So it is strictly
   recommended to perform these operations when the server is not running.

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
   it is advisable to slash square brackets or to quote command parameters if
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

.. _Running a slave server:

Slave mode
==========

Running the server as a slave is very straightforward as you usually
bootstrap zones over AXFR and thus avoid any manual zone operations.
In contrast to AXFR, when the incremental transfer finishes, it stores
the differences in the journal file and doesn't update the zone file
immediately but after the :ref:`zone_zonefile-sync` period elapses.

.. _Running a master server:

Master mode
===========

If you just want to check the zone files before starting, you can use::

    $ knotc zone-check example.com

For an approximate estimation of server's memory consumption, you can use::

    $ knotc zone-memstats example.com

This action prints the count of resource records, percentage of signed
records and finally estimation of memory consumption for each zone, unless
specified otherwise. Please note that the estimated values may differ from the
actual consumption. Also, for slave servers with incoming transfers
enabled, be aware that the actual memory consumption might be double
or higher during transfers.

.. _Editing zones:

Reading and editing zones
=========================

Knot DNS allows you to read or change zone contents online using server
control interface.

.. WARNING::
   Avoid concurrent zone file modification, and/or dynamic updates, and/or
   zone changing over control interface. Otherwise, the zone could be inconsistent.

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

To remove all records with a specific owner, or a specific rrset, or a
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
    If quotes are necessary for record data specification, don't forget to escape them::

       $ knotc zone-set example.com @ 3600 TXT \"v=spf1 a:mail.example.com -all\"

.. _Editing zone file:

Reading and editing the zone file safely
========================================

It's always possible to read and edit the zone contents via zone file manipulation.
However, it may lead to confusion if zone contents are continuously changing or
in case of operator's mistake. This paragraph describes a safe way to modify zone
by editing the zone file, taking advantage of zone freeze/thaw feature.::

    $ knotc zone-freeze example.com.
    $ while ! knotc zone-status example.com. +freeze | grep -q 'freeze: yes'; do sleep 1; done
    $ knotc zone-flush example.com.

After calling freeze to the zone, there still may be running zone operations (e.g. signing),
causing freeze pending. So we watch the zone status until frozen. Then we can flush the
frozen zone contents.

Now we open a text editor and perform desired changes to the zone file. It's necessary
to **increase SOA serial** in this step to keep consistency. Finally, we can load the
modified zone file and if successful, thaw the zone.::

    $ knotc zone-reload example.com.
    $ knotc zone-thaw example.com.

.. _Zone loading:

Zone loading
============

The process how the server loads a zone is influenced by the configuration of the
:ref:`zonefile-load <zone_zonefile-load>` and :ref:`journal-content <zone_journal-content>`
parameters (also DNSSEC signing applies), the existence of a zone file and journal
(and their relative out-of-dateness), and whether it is a cold start of the server
or a zone reload (e.g. invoked by the knotc interface). Please note that zone transfers
are not taken into account here – they are planned after the zone is loaded
(including AXFR bootstrap).

If the zone file exists and is not excluded by the configuration, it is first loaded
and according to its SOA serial number relevant journal changesets are applied.
If this is a zone reload and we have "`zonefile-load: difference`", the difference
between old and new contents is computed and stored into the journal like an update.
The zone file should be either unchaged since last load or changed with incremented
SOA serial. In the case of a decreased SOA serial, the load is interrupted with
an error; if unchanged, it is increased by the server.

If the procedure described above succeeds without errors, the resulting zone contents are (after potential DNSSEC signing)
used as the new zone.

The option "`journal-content: all`" lets the server, beside better performance, to keep
track of the zone contents also across server restarts. It makes the cold start
effectively work like a zone reload with the old contents loaded from the journal
(unless this is the very first start with the zone not yet saved into the journal).

.. _Journal behaviour:

Journal behaviour
=================

The zone journal keeps some history of changes made to the zone. It is useful for
responding to IXFR queries. Also if :ref:`zone file flush <zone_zonefile-sync>` is disabled,
journal keeps diff between the zone file and zone for the case of server shutdown.
The history is stored in changesets – diffs of zone contents between two
(usually subsequent) zone serials.

Journals of all zones are stored in a common LMDB database. Huge changesets are
split into 70 KiB [#fn-hc]_ blocks to prevent fragmentation of the DB.
Journal does each operation in one transaction to keep consistency of the DB and performance.
The exception is when store transaction exceeds 5 % of the whole DB mapsize, it is split into multiple ones
and some dirty-chunks-management involves.

Each zone journal has own :ref:`usage limit <zone_max-journal-usage>`
on how much DB space it may occupy. Before hitting the limit,
changesets are stored one-by-one and whole history is linear. While hitting the limit,
the zone is flushed into the zone file, and oldest changesets are deleted as needed to free
some space. Actually, twice [#fn-hc]_ the needed amount is deleted to
prevent too frequent deletes. Further zone file flush is invoked after the journal runs out of deletable
"flushed changesets".

If :ref:`zone file flush <zone_zonefile-sync>` is disabled, then instead of flushing the zone, the journal tries to
save space by merging older changesets into one. It works well if the changes rewrite
each other, e.g. periodically changing few zone records, re-signing whole zone...
The difference between the zone file and the zone is thus preserved, even if journal deletes some
older changesets.

If the journal is used to store both zone history and contents, a special changeset
is present with zone contents. When the journal gets full, the changes are merged into this
special changeset.

There is also a :ref:`safety hard limit <template_max-journal-db-size>` for overall
journal database size, but it's strongly recommended to set the per-zone limits in
a way to prevent hitting this one. For LMDB, it's hard to recover from the
database-full state. For wiping one zone's journal, see *knotc zone-purge +journal*
command.

.. [#fn-hc] This constant is hardcoded.

.. _Handling, zone file, journal, changes, serials:

Handling zone file, journal, changes, serials
=============================================

Some configuration options regarding the zone file and journal, together with operation
procedures, might lead to unexpected results. This chapter shall point out
some interference and both recommend and warn before some combinations thereof.
Unfortunately, there is no optimal combination of configuration options,
every approach has some disadvantages.

Example 1
---------

Keep the zone file updated::

   zonefile-sync: 0
   zonefile-load: whole
   journal-content: changes

This is actually setting default values. The user can always check the current zone
contents in the zonei file, and also modify it (recommended with server turned-off or
taking the :ref:`safe way<Editing zone file>`). Journal serves here just as a source of
history for slaves' IXFR. Some users dislike that the server overwrites their prettily
prepared zone file.

Example 2
---------

Zonefileless setup::

   zonefile-sync: -1
   zonefile-load: none
   journal-content: all

Zone contents are stored just in the journal. The zone is updated by DDNS,
zone transfer, or via the control interface. The user might have filled the
zone contents initially from a zone file by setting "zonefile-load: whole" temporarily.
It's also a good setup for slaves. Anyway, it's recommended to carefully tune
the journal-size-related options to avoid surprises of journal getting full.

Example 3
---------

Input-only zone file::

   zonefile-sync: -1
   zonefile-load: difference
   journal-content: changes

The user can make changes to the zone by editing the zone file, and his pretty zone file
gets never overwritten and filled with DNSSEC-related autogenerated records – they are
only stored in the journal.

The zone file's SOA serial must be properly set to a number which is higher than the
current SOA serial in the zone (not in the zone file) if manually updated!

.. NOTE::
   In the case of "zonefile-load: difference-no-serial", the SOA serial is
   handled by the server automatically during server reload.

.. _DNSSEC Key states:

DNSSEC key states
=================

During its lifetime, DNSSEC key finds itself in different states. Most of the time it
is usually used for signing the zone and published in the zone. In order to change
this state, one type of a key rollover is necessary, and during this rollover,
the key goes through various states, with respect to the rollover type and also the
state of the other key being rolled-over.

First, let's list the states of the key being rolled-in.

Standard states:

- ``active`` — The key is used for signing.
- ``published`` — The key is published in the zone, but not used for signing.
- ``ready`` (only for KSK) — The key is published in the zone and used for signing. The
  old key is still active, since we are waiting for the DS records in the parent zone to be
  updated (i.e. "KSK submission").

Special states for algorithm rollover:

- ``pre-active`` — The key is not yet published in the zone, but it's used for signing the zone.
- ``published`` — The key is published in the zone, and it's still used for signing since the
  pre-active state.

Second, we list the states of the key being rolled-out.

Standard states:

- ``retire-active`` — The key is still used for signing and published in the zone, waiting for
  the updated DS records in parent zone to be acked by resolvers (KSK case) or synchronizing
  with KSK during algorithm rollover (ZSK case).
- ``retired`` — The key is no longer used for signing, but still published in the zone.
- ``removed`` — The key is not used in any way (in most cases such keys are deleted immediately).

Special states for algorithm rollover:

- ``post-active`` — The key is no longer published in the zone, but still used for signing.

The states listed above are relevant for :doc:`keymgr <man_keymgr>` operations like generating
a key, setting its timers and listing KASP database.

On the other hand, the key "states" displayed in the server log lines while zone signing
are not according to listed above, but just a hint what the key is currently used to
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

The algorithm rollover happens when the policy :ref:`algorithm<policy_algorithm>`
field is updated to a different value.

The signing scheme rollover happens when the policy :ref:`singing scheme<policy_single-type-signing>`
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

.. _DNSSEC KSK rollover example:

KSK rollover example
--------------------

Let's start with the following set of keys::

  2017-10-24T15:40:48 info: [example.com.] DNSSEC, key, tag  4700, algorithm RSASHA256, KSK, public, active
  2017-10-24T15:40:48 info: [example.com.] DNSSEC, key, tag 30936, algorithm RSASHA256, public, active

The last fields hint the key state: ``public`` denotes a key that will be presented
as the DNSKEY record, ``ready`` means that CDS/CDNSKEY records were created,
``active`` tells us if the key is used for signing.

Upon the zone's KSK lifetime expiration, the rollover continues along the
lines of :rfc:`6781#section-4.1.2`::

  2017-10-24T15:41:17 info: [example.com.] DNSSEC, signing zone
  2017-10-24T15:41:18 info: [example.com.] DNSSEC, KSK rollover started
  2017-10-24T15:41:18 info: [example.com.] DNSSEC, key, tag  6674, algorithm RSASHA256, KSK, public
  2017-10-24T15:41:18 info: [example.com.] DNSSEC, key, tag  4700, algorithm RSASHA256, KSK, public, active
  2017-10-24T15:41:18 info: [example.com.] DNSSEC, key, tag 30936, algorithm RSASHA256, public, active
  2017-10-24T15:41:18 info: [example.com.] DNSSEC, signing started
  2017-10-24T15:41:18 info: [example.com.] DNSSEC, successfully signed
  2017-10-24T15:41:18 info: [example.com.] DNSSEC, next signing at 2017-10-24T15:41:22
  ...
  2017-10-24T15:41:22 info: [example.com.] DNSSEC, signing zone
  2017-10-24T15:41:22 info: [example.com.] DNSSEC, key, tag  4700, algorithm RSASHA256, KSK, public, active
  2017-10-24T15:41:22 info: [example.com.] DNSSEC, key, tag  6674, algorithm RSASHA256, KSK, public, ready, active
  2017-10-24T15:41:22 info: [example.com.] DNSSEC, key, tag 30936, algorithm RSASHA256, public, active
  2017-10-24T15:41:22 info: [example.com.] DNSSEC, signing started
  2017-10-24T15:41:22 info: [example.com.] DNSSEC, successfully signed
  2017-10-24T15:41:22 info: [example.com.] DNSSEC, next signing at 2017-10-24T15:41:23
  2017-10-24T15:41:22 notice: [example.com.] DNSSEC, KSK submission, waiting for confirmation

At this point new KSK has to be submitted to the parent zone. Knot detects the updated parent's DS
record automatically (and waits for additional period of the DS's TTL before retiring the old key)
if :ref:`parent DS check<Submission section>` is configured, otherwise the
operator must confirm it manually with ``knotc zone-ksk-submitted``::

  2017-10-24T15:41:23 notice: [example.com.] DNSSEC, KSK submission, confirmed
  2017-10-24T15:41:23 info: [example.com.] DNSSEC, signing zone
  2017-10-24T15:41:23 info: [example.com.] DNSSEC, key, tag  6674, algorithm RSASHA256, KSK, public, active
  2017-10-24T15:41:23 info: [example.com.] DNSSEC, key, tag  4700, algorithm RSASHA256, KSK, public, active
  2017-10-24T15:41:23 info: [example.com.] DNSSEC, key, tag 30936, algorithm RSASHA256, public, active
  2017-10-24T15:41:23 info: [example.com.] DNSSEC, signing started
  2017-10-24T15:41:23 info: [example.com.] DNSSEC, zone is up-to-date
  2017-10-24T15:41:23 info: [example.com.] DNSSEC, next signing at 2017-10-24T15:41:28
  ...
  2017-10-24T15:41:28 info: [example.com.] DNSSEC, signing zone
  2017-10-24T15:41:28 info: [example.com.] DNSSEC, key, tag  4700, algorithm RSASHA256, KSK, public
  2017-10-24T15:41:28 info: [example.com.] DNSSEC, key, tag  6674, algorithm RSASHA256, KSK, public, active
  2017-10-24T15:41:28 info: [example.com.] DNSSEC, key, tag 30936, algorithm RSASHA256, public, active
  2017-10-24T15:41:28 info: [example.com.] DNSSEC, signing started
  2017-10-24T15:41:28 info: [example.com.] DNSSEC, successfully signed
  2017-10-24T15:41:28 info: [example.com.] DNSSEC, next signing at 2017-10-24T15:41:33
  ...
  2017-10-24T15:41:33 info: [example.com.] DNSSEC, signing zone
  2017-10-24T15:41:33 info: [example.com.] DNSSEC, key, tag  6674, algorithm RSASHA256, KSK, public, active
  2017-10-24T15:41:33 info: [example.com.] DNSSEC, key, tag 30936, algorithm RSASHA256, public, active
  2017-10-24T15:41:33 info: [example.com.] DNSSEC, signing started
  2017-10-24T15:41:33 info: [example.com.] DNSSEC, successfully signed
  2017-10-24T15:41:33 info: [example.com.] DNSSEC, next signing at 2017-10-24T15:41:47

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

Algorithm rollover example
--------------------------

Let's start with the following set of keys::

  2017-10-24T14:53:06 info: [example.com.] DNSSEC, key, tag 65225, algorithm RSASHA256, KSK, public, active
  2017-10-24T14:53:06 info: [example.com.] DNSSEC, key, tag 47014, algorithm RSASHA256, public, active

When the zone's DNSSEC policy algorithm is changed to ``ECDSAP256SHA256`` and the
server is reloaded, the rollover continues along the lines of :rfc:`6781#section-4.1.4`::

  2017-10-24T14:53:26 info: [example.com.] DNSSEC, algorithm rollover started
  2017-10-24T14:53:26 info: [example.com.] DNSSEC, key, tag 34608, algorithm ECDSAP256SHA256, KSK
  2017-10-24T14:53:26 info: [example.com.] DNSSEC, key, tag 13674, algorithm ECDSAP256SHA256, active
  2017-10-24T14:53:26 info: [example.com.] DNSSEC, key, tag 65225, algorithm RSASHA256, KSK, public, active
  2017-10-24T14:53:26 info: [example.com.] DNSSEC, key, tag 47014, algorithm RSASHA256, public, active
  2017-10-24T14:53:26 info: [example.com.] DNSSEC, signing started
  2017-10-24T14:53:26 info: [example.com.] DNSSEC, successfully signed
  2017-10-24T14:53:26 info: [example.com.] DNSSEC, next signing at 2017-10-24T14:53:34
  ...
  2017-10-24T14:53:34 info: [example.com.] DNSSEC, signing zone
  2017-10-24T14:53:34 info: [example.com.] DNSSEC, key, tag 34608, algorithm ECDSAP256SHA256, KSK, public, active
  2017-10-24T14:53:34 info: [example.com.] DNSSEC, key, tag 13674, algorithm ECDSAP256SHA256, public, active
  2017-10-24T14:53:34 info: [example.com.] DNSSEC, key, tag 65225, algorithm RSASHA256, KSK, public, active
  2017-10-24T14:53:34 info: [example.com.] DNSSEC, key, tag 47014, algorithm RSASHA256, public, active
  2017-10-24T14:53:34 info: [example.com.] DNSSEC, signing started
  2017-10-24T14:53:34 info: [example.com.] DNSSEC, successfully signed
  2017-10-24T14:53:34 info: [example.com.] DNSSEC, next signing at 2017-10-24T14:53:44
  ...
  2017-10-24T14:53:44 info: [example.com.] DNSSEC, signing zone
  2017-10-24T14:53:44 info: [example.com.] DNSSEC, key, tag 34608, algorithm ECDSAP256SHA256, KSK, public, ready, active
  2017-10-24T14:53:44 info: [example.com.] DNSSEC, key, tag 13674, algorithm ECDSAP256SHA256, public, active
  2017-10-24T14:53:44 info: [example.com.] DNSSEC, key, tag 65225, algorithm RSASHA256, KSK, public, active
  2017-10-24T14:53:44 info: [example.com.] DNSSEC, key, tag 47014, algorithm RSASHA256, public, active
  2017-10-24T14:53:44 info: [example.com.] DNSSEC, signing started
  2017-10-24T14:53:44 info: [example.com.] DNSSEC, successfully signed
  2017-10-24T14:53:44 info: [example.com.] DNSSEC, next signing at 2017-10-31T13:52:37
  2017-10-24T14:53:44 notice: [example.com.] DNSSEC, KSK submission, waiting for confirmation

Again, KSK submission follows as in :ref:`KSK rollover example<DNSSEC ksk rollover example>`::

  2017-10-24T14:54:20 notice: [example.com.] DNSSEC, KSK submission, confirmed
  2017-10-24T14:54:20 info: [example.com.] DNSSEC, signing zone
  2017-10-24T14:54:20 info: [example.com.] DNSSEC, key, tag 34608, algorithm ECDSAP256SHA256, KSK, public, active
  2017-10-24T14:54:20 info: [example.com.] DNSSEC, key, tag 13674, algorithm ECDSAP256SHA256, public, active
  2017-10-24T14:54:20 info: [example.com.] DNSSEC, key, tag 65225, algorithm RSASHA256, KSK, public, active
  2017-10-24T14:54:20 info: [example.com.] DNSSEC, key, tag 47014, algorithm RSASHA256, public, active
  2017-10-24T14:54:20 info: [example.com.] DNSSEC, signing started
  2017-10-24T14:54:21 info: [example.com.] DNSSEC, zone is up-to-date
  2017-10-24T14:54:21 info: [example.com.] DNSSEC, next signing at 2017-10-24T14:54:30
  ...
  2017-10-24T14:54:30 info: [example.com.] DNSSEC, signing zone
  2017-10-24T14:54:30 info: [example.com.] DNSSEC, key, tag 34608, algorithm ECDSAP256SHA256, KSK, public, active
  2017-10-24T14:54:30 info: [example.com.] DNSSEC, key, tag 13674, algorithm ECDSAP256SHA256, public, active
  2017-10-24T14:54:30 info: [example.com.] DNSSEC, key, tag 65225, algorithm RSASHA256, KSK
  2017-10-24T14:54:30 info: [example.com.] DNSSEC, key, tag 47014, algorithm RSASHA256, active
  2017-10-24T14:54:30 info: [example.com.] DNSSEC, signing started
  2017-10-24T14:54:30 info: [example.com.] DNSSEC, successfully signed
  2017-10-24T14:54:30 info: [example.com.] DNSSEC, next signing at 2017-10-24T14:54:40
  ...
  2017-10-24T14:54:40 info: [example.com.] DNSSEC, signing zone
  2017-10-24T14:54:40 info: [example.com.] DNSSEC, key, tag 34608, algorithm ECDSAP256SHA256, KSK, public, active
  2017-10-24T14:54:40 info: [example.com.] DNSSEC, key, tag 13674, algorithm ECDSAP256SHA256, public, active
  2017-10-24T14:54:40 info: [example.com.] DNSSEC, signing started
  2017-10-24T14:54:40 info: [example.com.] DNSSEC, successfully signed
  2017-10-24T14:54:40 info: [example.com.] DNSSEC, next signing at 2017-10-31T13:53:26

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
but different ZSKs. The KSK rollovers may take place at slightly different time for each of the zones,
but the resulting new KSK will be shared again among all of them.

If we have zones already having their keys, turning on the shared KSK feature triggers no action.
But when a KSK rollover takes place, they will use the same new key afterwards.

.. _DNSSEC Delete algorithm:

DNSSEC delete algorithm
=======================

This is a way how to "disconnect" a signed zone from DNSSEC-aware parent zone.
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
of :doc:`keymgr <man_keymgr>` utility.

Pre-requisites
--------------

For the ZSK side (i.e. the operator of the DNS server), the pre-requisites are:

- properly configured :ref:`DNSSEC policy <Policy section>` (e.g. :ref:`zsk-lifetime <policy_zsk-lifetime>`),
- :ref:`manual <policy_manual>` set to `on`
- :ref:`offline-ksk <policy_offline-ksk>` set to `on`
- :ref:`dnskey-ttl <policy_dnskey-ttl>` and :ref:`zone-max-ttl <policy_zone-max-ttl>` set up explicitly
- a complete KASP DB with just ZSK(s)

For the KSK side (i.e. the operator of the KSK signer), the pre-requisites are:

- Knot configuration equal to the ZSK side (at least relevant parts of corresponding
  :ref:`policy <Policy section>`, :ref:`zone <Zone section>`, and :ref:`template <Template section>`
  sections must be identical)
- a KASP DB with the KSK(s)

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

5. Use the ``knotc zone-sign`` command to trigger a zone re-sign on the ZSK-side and set up the future re-signing events correctly.::

    $ knotc -c /path/to/ZSK/side.conf zone-sign example.com.

6. Now the future ZSKs and DNSKEY records with signatures are ready in KASP DB for later usage.
   Knot automatically uses them in correct time intervals.
   The entire procedure must to be repeated before the time period selected at the beginning passes,
   or whenever a configuration is changed significantly. Over-importing new SKR across some previously-imported
   one leads to deleting the old offline records.

.. _DNSSEC Export Import  KASP DB:

Export/import  KASP DB
======================

If you would like make a backup of your KASP DB or transfer your cryptographic
keys to a different server,
you may utilize the ``mdb_dump`` and ``mdb_load`` tools provided by the
`lmdb-utils <https://packages.ubuntu.com/bionic/lmdb-utils>`_
package on Ubuntu and Debian or by the `lmdb <https://rpms.remirepo.net/rpmphp/zoom.php?rpm=lmdb>`_
package on Fedora, CentOS and RHEL.
These tools allow you to convert the contents of any LMDB database to a portable plain text format
which can be imported to any other LMDB database. Note that the `keys` subdirectory of the
:ref:`template_kasp-db` directory containing the \*.pem files has to be copied separately.

.. NOTE::
   Make sure to freeze DNSSEC events on a running server prior to applying the following
   commands to its  KASP DB. Use the ``knotc zone-freeze`` and ``knotc zone-thaw`` commands
   as described in :ref:`Editing zone file`.

Use the ``mdb_dump -a`` command with the configured :ref:`template_kasp-db` directory
as an argument to convert the contents of the LMDB database to a portable text format:

.. code-block:: console

   $ mdb_dump -a /path/to/keys

Save the output of the command to a text file. You may then import the file
into a different LMDB database using the ``mdb_load -f`` command, supplying the path
to the file and the path to the database directory as arguments:

.. code-block:: console

    $ mdb_load -f /path/to/dump_file /path/to/keys

.. NOTE::
   Depending on your use case, it might be necessary to call ``knotc zone-sign``
   (e.g. to immediately sign the zones with the new imported keys) or ``knotc zone-reload``
   (e.g. to refresh DNSSEC signatures generated by the :ref:`geoip module<mod-geoip>`)
   after importing new content into the KASP DB of a running server.

.. _Controlling running daemon:

Daemon controls
===============

Knot DNS was designed to allow server reconfiguration on-the-fly
without interrupting its operation. Thus it is possible to change
both configuration and zone files and also add or remove zones without
restarting the server. This can be done with::

    $ knotc reload

If you want to refresh the slave zones, you can do this with::

    $ knotc zone-refresh

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

To show all supported counters even with 0 value use the force option.

A simple periodic statistic dumping to a YAML file can also be enabled. See
:ref:`statistics_section` for the configuration details.

As the statistics data can be accessed over the server control socket,
it is possible to create an arbitrary script (Python is supported at the moment)
which could, for example, publish the data in the JSON format via HTTP(S)
or upload the data to a more efficient time series database. Take a look into
the python folder of the project for these scripts.
