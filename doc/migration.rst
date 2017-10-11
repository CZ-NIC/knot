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
kdig only! To build the dnstap query module, ``--with-module-dnstap`` have
to be used.

Since Knot DNS version 2.5.0 each query module can be configured to be:

- disabled: ``--with-module-``\ MODULE_NAME\ ``=no``
- embedded: ``--with-module-``\ MODULE_NAME\ ``=yes``
- external: ``--with-module-``\ MODULE_NAME\ ``=shared`` (excluding
  ``dnsproxy`` and ``onlinesign``)

The ``--with-timer-mapsize`` configure option was replaced with the runtime
:ref:`template_max-timer-db-size` configuration option.

.. _KASP DB migration:

KASP DB migration
-----------------

Knot DNS version 2.4.x and earlier uses JSON files to store DNSSEC keys metadata,
one for each zone. 2.5.x versions store those in binary format in a LMDB, all zones
together. The migration is possible with ``pykeymgr`` script::

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
   request BIND to flush the zone into the zone file: ``rndc flush
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
      The server can be run under a dedicated user account, usually ``knot``.
      As the server requires read-write access to the KASP database, the
      permissions must be set correctly. This can be achieved for instance by
      executing all KASP database management commands under sudo::

      $ sudo -u knot keymgr ...

4. Follow :ref:`Automatic DNSSEC signing` steps to configure DNSSEC signing.
