.. highlight:: none
.. _Migration from other DNS servers:

********************************
Migration from other DNS servers
********************************

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

   $ kkeymgr -d path/to/keydir example.com. import-bind path/to/Kexample.com.+013+11111
   $ kkeymgr -d path/to/keydir example.com. import-bind path/to/Kexample.com.+013+22222
   $ ...
   $ kkeymgr -d path/to/keydir example.com. list

   .. NOTE::
      The server can be run under a dedicated user account, usually ``knot``.
      As the server requires read-write access to the KASP database, the
      permissions must be set correctly. This can be achieved for instance by
      executing all KASP database management commands under sudo::

      $ sudo -u knot kkeymgr ...

4. Follow :ref:`Automatic DNSSEC signing` steps to configure DNSSEC signing.
