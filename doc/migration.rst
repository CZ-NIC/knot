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

2. Copy the fresh zone file into the zones storage directory of Knot
   DNS. Its default location is ``/var/lib/knot``.

3. Initialize DNSSEC KASP database (default location is ``/var/lib/knot/keys``
   and create a dedicated signing policy for the imported zones with manual
   key management::

   $ cd /var/lib/knot/keys
   $ keymgr init
   $ keymgr policy add bind manual true

   .. NOTE::
      The server can be run under a dedicated user account, usually ``knot``.
      As the server requires read-write access to the KASP database, the
      permissions must be set correctly. This can be achieved for instance by
      executing all KASP database management commands under sudo::

      $ sudo -u knot keymgr ...

4. For each imported zone, create an entry in the KASP database and import
   all existing keys. Make sure that all keys were configured correctly::

   $ keymgr zone add example.com policy bind
   $ keymgr zone key import example.com path/to/Kexample.com.+013+11111
   $ keymgr zone key import example.com path/to/Kexample.com.+013+22222
   $ ...
   $ keymgr zone key list example.com

5. Add the zone into the Knot DNS configuration. Zone configuration must
   include correct zone file path (option :ref:`file<zone_file>`) and KASP
   database location (option :ref:`kasp-db<zone_kasp_db>`). You can follow
   this configuration file snippet::

    zone:
      - domain: example.com
        storage: /var/lib/knot
        kasp-db: /var/lib/knot/keys
        file: example.com.zone
        dnssec-signing: on

6. Start Knot DNS and check the log files to verify that everything went right.

7. Optionally, review the used KASP policy and enable automatic key management::

   $ keymgr policy set bind manual false
   $ sudo knotc reload
