.. highlight:: none
.. _Migration:

*********
Migration
*********

.. _Upgrade 2.4.x to 2.5.x:

Upgrade 2.4.x to 2.5.x
======================

This chapter describes some steps necessary after upgrading Knot DNS from
version 2.4.x to 2.5.x.

.. _Building changes:

Building changes
----------------

The ``--enable-dnstap`` configure option now enables the dnstap support in
:doc:`kdig<man_kdig>` only! To build the dnstap query module, ``--with-module-dnstap``
have to be used.

Since Knot DNS version 2.5.0 each query module can be configured to be:

- disabled: ``--with-module-``\ MODULE_NAME\ ``=no``
- embedded: ``--with-module-``\ MODULE_NAME\ ``=yes``
- external: ``--with-module-``\ MODULE_NAME\ ``=shared`` (excluding
  ``dnsproxy`` and ``onlinesign``)

The ``--with-timer-mapsize`` configure option was replaced with the runtime
``template.max-timer-db-size`` configuration option.

.. _KASP DB migration:

KASP DB migration
-----------------

Knot DNS version 2.4.x and earlier uses JSON files to store DNSSEC keys metadata,
one for each zone. 2.5.x versions store those in binary format in a LMDB, all zones
together. The migration is possible with the
`pykeymgr <https://gitlab.nic.cz/knot/knot-dns/blob/2.6/src/utils/pykeymgr/pykeymgr.in>`_
script::

   $ pykeymgr -i path/to/keydir

The path to KASP DB directory is configuration-dependent, usually it is the ``keys``
subdirectory in the zone storage.

In rare installations, the JSON files might be spread across more directories. In such
case, it is necessary to put them together into one directory and migrate at once.

.. _Configuration changes 2.5:

Configuration changes
---------------------

It is no longer possible to configure KASP DB per zone or in a non-default
template. Ensure just one common KASP DB configuration in the default
template.

As Knot DNS version 2.5.0 brings dynamically loaded modules, some modules
were renamed for technical reasons. So it is necessary to rename all
occurrences (module section names and references from zones or templates)
of the following module names in the configuration::

   mod-online-sign -> mod-onlinesign

   mod-synth-record -> mod-synthrecord

.. _Upgrade 2.5.x to 2.6.x:

Upgrade 2.5.x to 2.6.x
======================

Upgrading from Knot DNS version 2.5.x to 2.6.x is almost seamless.

.. _Configuration changes 2.6:

Configuration changes
---------------------

The ``dsa`` and ``dsa-nsec3-sha1`` algorithm values are no longer supported
by the :ref:`policy_algorithm` option.

The ``ixfr-from-differences`` zone/template option was deprecated in favor of
the :ref:`zone_zonefile-load` option.

.. _Upgrade 2.6.x to 2.7.x:

Upgrade 2.6.x to 2.7.x
======================

Upgrading from Knot DNS version 2.6.x to 2.7.x is seamless if no obsolete
configuration or module rosedb is used.

.. _Upgrade 2.7.x to 2.8.x:

Upgrade 2.7.x to 2.8.x
======================

Upgrading from Knot DNS version 2.7.x to 2.8.x is seamless.

However, if the previous version was migrated (possibly indirectly)
from version 2.5.x, the format of the keys stored in
Keys And Signature Policy Database
is no longer compatible and needs to be updated.

The easiest ways to update how keys are stored in KASP DB is to modify
with Keymgr version 2.7.x
some of each key's parameters in an undamaging way, e.g.::

    $ keymgr example.com. list
    $ keymgr example.com. set <keyTag> created=1
    $ keymgr example.com. set <keyTag2> created=1
    ...

.. _Upgrade 2.8.x to 2.9.x:

Upgrade 2.8.x to 2.9.x
======================

Upgrading from Knot DNS version 2.8.x to 2.9.x is almost seamless but check
the following changes first.

Configuration changes
---------------------

- Imperfect runtime reconfiguration of :ref:`server_udp-workers`,
  :ref:`server_tcp-workers`, and :ref:`server_listen`
  is no longer supported.

- Replaced options (with backward compatibility):

   .. csv-table::
      :header: Old section, Old item name, New section, New item name
      :widths: 35, 60, 35, 60

      :ref:`server<Server section>`     , ``tcp-reply-timeout`` [s] , :ref:`server<Server section>`     , :ref:`server_tcp-remote-io-timeout` [ms]
      :ref:`server<Server section>`     , ``max-tcp-clients``       , :ref:`server<Server section>`     , :ref:`server_tcp-max-clients`
      :ref:`server<Server section>`     , ``max-udp-payload``       , :ref:`server<Server section>`     , :ref:`server_udp-max-payload`
      :ref:`server<Server section>`     , ``max-ipv4-udp-payload``  , :ref:`server<Server section>`     , :ref:`server_udp-max-payload-ipv4`
      :ref:`server<Server section>`     , ``max-ipv6-udp-payload``  , :ref:`server<Server section>`     , :ref:`server_udp-max-payload-ipv6`
      :ref:`template<Template section>` , ``journal-db``            , :ref:`database<Database section>` , :ref:`database_journal-db`
      :ref:`template<Template section>` , ``journal-db-mode``       , :ref:`database<Database section>` , :ref:`database_journal-db-mode`
      :ref:`template<Template section>` , ``max-journal-db-size``   , :ref:`database<Database section>` , :ref:`database_journal-db-max-size`
      :ref:`template<Template section>` , ``kasp-db``               , :ref:`database<Database section>` , :ref:`database_kasp-db`
      :ref:`template<Template section>` , ``max-kasp-db-size``      , :ref:`database<Database section>` , :ref:`database_kasp-db-max-size`
      :ref:`template<Template section>` , ``timer-db``              , :ref:`database<Database section>` , :ref:`database_timer-db`
      :ref:`template<Template section>` , ``max-timer-db-size``     , :ref:`database<Database section>` , :ref:`database_timer-db-max-size`
      :ref:`zone<Zone section>`         , ``max-journal-usage``     , :ref:`zone<Zone section>`         , :ref:`zone_journal-max-usage`
      :ref:`zone<Zone section>`         , ``max-journal-depth``     , :ref:`zone<Zone section>`         , :ref:`zone_journal-max-depth`
      :ref:`zone<Zone section>`         , ``max-zone-size``         , :ref:`zone<Zone section>`         , :ref:`zone_zone-max-size`
      :ref:`zone<Zone section>`         , ``max-refresh-interval``  , :ref:`zone<Zone section>`         , :ref:`zone_refresh-max-interval`
      :ref:`zone<Zone section>`         , ``min-refresh-interval``  , :ref:`zone<Zone section>`         , :ref:`zone_refresh-min-interval`

- Removed options (no backward compatibility):

  - ``server.tcp-handshake-timeout``
  - ``zone.request-edns-option``

- New default values for:

  - :ref:`server_tcp-workers`
  - :ref:`server_tcp-max-clients`
  - :ref:`server_udp-max-payload`
  - :ref:`server_udp-max-payload-ipv4`
  - :ref:`server_udp-max-payload-ipv6`

- New DNSSEC policy option :ref:`policy_rrsig-pre-refresh` may affect
  configuration validity, which is ``rrsig-refresh + rrsig-pre-refresh < rrsig-lifetime``

Miscellaneous changes
---------------------

- Memory use estimation via ``knotc zone-memstats`` was removed
- Based on `<https://tools.ietf.org/html/draft-ietf-dnsop-server-cookies>`_
  the module :ref:`DNS Cookies<mod-cookies>` was updated to be interoperable
- Number of open files limit is set to 1048576 in upstream packages

.. _Upgrade 2.9.x to 3.0.x:

Upgrade 2.9.x to 3.0.x
======================

Knot DNS version 3.0.x is functionally compatible with 2.9.x with the following
exceptions.

ACL
---

Configuration option :ref:`acl_update-owner-name` is newly FQDN-sensitive.
It means that values ``a.example.com`` and ``a.example.com.`` are not equivalent.

Module synthrecord
------------------

:ref:`Reverse IPv6 address shortening<mod-synthrecord_reverse-short>` is enabled by default.
For example, the module generates::

  dynamic-2620-0-b61-100--1.test. 400 IN AAAA 2620:0:b61:100::1

instead of::

  dynamic-2620-0000-0b61-0100-0000-0000-0000-0001.test. 400 IN AAAA 2620:0:b61:100::1

Query module API change
-----------------------

The following functions require additional parameter (thread id – ``qdata->params->thread_id``)
on the second position::

  knotd_mod_stats_incr()
  knotd_mod_stats_decr()
  knotd_mod_stats_store()

Building notes
--------------

- The embedded library *LMDB* is no longer part of the source code. Almost every
  modern operating system has a sufficient version of this library.
- DoH support in kdig requires optional library *libnghttp2*.
- XDP support on Linux requires optional library *libbpf >= 0.0.6*. If not available,
  an embedded library can be used via ``--enable-xdp=yes`` configure option.

.. _Upgrade 3.0.x to 3.1.x:

Upgrade 3.0.x to 3.1.x
======================

Knot DNS version 3.1.x is functionally compatible with 3.0.x with the following
exceptions.

Configuration changes
---------------------

- Automatic SOA serial incrementation (``zonefile-load: difference-no-serial``)
  requires having full zone stored in the journal (``journal-content: all``).
  This change is necessary for reliable operation.

- Replaced options (with backward compatibility):

   .. csv-table::
      :header: Old section, Old item name, New section, New item name
      :widths: 40, 60, 40, 60

      :ref:`server<Server section>`, ``listen-xdp``, :ref:`xdp<XDP section>`, :ref:`xdp_listen`

- Ignored obsolete options (with a notice log):

  - ``server.max-zone-size``
  - ``server.max-journal-depth``
  - ``server.max-journal-usage``
  - ``server.max-refresh-interval``
  - ``server.min-refresh-interval``
  - ``server.max-ipv4-udp-payload``
  - ``server.max-ipv6-udp-payload``
  - ``server.max-udp-payload``
  - ``server.max-tcp-clients``
  - ``server.tcp-reply-timeout``
  - ``template.journal-db``
  - ``template.kasp-db``
  - ``template.timer-db``
  - ``template.max-journal-db-size``
  - ``template.max-timer-db-size``
  - ``template.max-kasp-db-size``
  - ``template.journal-db-mode``

- Silently ignored obsolete options:

  - ``server.tcp-handshake-timeout``
  - ``zone.disable-any``

Zone backup and restore
-----------------------

The online backup format has changed slightly since 3.0 version. For zone-restore
from backups in the previous format, it's necessary to set the *-f* option.
Offline restore procedure of zone files from online backups is different than
what it was before. The details are described in :ref:`Data and metadata backup`.

Building notes
--------------

- The configure option ``--enable-xdp=yes`` has slightly changed its semantics.
  It first tries to find an external library *libbpf*. If it's not detected,
  the embedded one is used instead.
- The kxdpgun tool also depends on library *libmnl*.

Packaging
---------

Users who use module :ref:`geoip<mod-geoip>` or :ref:`dnstap<mod-dnstap>` might
need installing an additional package with the module.

.. _Upgrade 3.1.x to 3.2.x:

Upgrade 3.1.x to 3.2.x
======================

Knot DNS version 3.2.x is functionally compatible with 3.1.x with the following
exceptions.

Configuration changes
---------------------

- Ignored obsolete option (with a notice log):

  - ``server.listen-xdp``

Utilities:
----------

- :doc:`knotc<man_knotc>` prints simplified zones status by default. Use ``-e``
  for full output.
- :doc:`keymgr<man_keymgr>` uses the brief key listing mode by default. Use ``-e``
  for full output.
- :doc:`keymgr<man_keymgr>` parameter ``-d`` was renamed to ``-D``.
- :doc:`kjournalprint<man_kjournalprint>` parameter ``-c`` was renamed to ``-H``.

Packaging
---------

- Linux distributions Debian 9 and Ubuntu 16.04 are no longer supported.

- Packages for CentOS 7 are stored in a separate COPR repository
  ``cznic/knot-dns-latest-centos7``.

- Utilities :doc:`kzonecheck<man_kzonecheck>`, :doc:`kzonesign<man_kzonesign>`,
  and :doc:`knsec3hash<man_knsec3hash>` are located in a new ``knot-dnssecutils``
  package.

Python
------

- Compatibility with Python 2 was removed.

.. _Knot DNS for BIND users:

Knot DNS for BIND users
=======================

.. _Automatic DNSSEC signing:

Automatic DNSSEC signing
------------------------

Migrating automatically signed zones from BIND to Knot DNS requires copying
up-to-date zone files from BIND, importing existing private keys, and updating
server configuration:

1. To obtain current content of the zone which is being migrated,
   request BIND to flush the zone into the zone file: ``rndc sync
   example.com``.

   .. NOTE::
      If dynamic updates (DDNS) are enabled for the given zone, you
      might need to freeze the zone before flushing it. That can be done
      similarly::

      $ rndc freeze example.com

2. Copy the fresh zone file into the zones :ref:`storage<zone_storage>`
   directory of Knot DNS.

3. Import all existing zone keys into the KASP database. Make sure that all
   the keys were imported correctly::

   $ keymgr example.com. import-bind path/to/Kexample.com.+013+11111
   $ keymgr example.com. import-bind path/to/Kexample.com.+013+22222
   $ ...
   $ keymgr example.com. list

   .. NOTE::
      If the server configuration file or database is not at the default location,
      add a configuration parameter (-c or -C). See :doc:`keymgr<man_keymgr>`
      for more info about required access rights to the key files.

4. Follow :ref:`Automatic DNSSEC signing` steps to configure DNSSEC signing.
