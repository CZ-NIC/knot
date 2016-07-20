.. _Knot DNS Configuration Reference:

********************************
Knot DNS Configuration Reference
********************************

This reference describes every configuration option in Knot DNS server.

.. _system:

``system`` Statement
====================

The ``system`` statement contains general options related to the
operating system and other general options which do not fit anywhere
else.

.. _system Syntax:

``system`` Syntax
-----------------

::

    system {
      [ identity ( on | "string" ); ]
      [ version ( on | "string" ); ]
      [ nsid ( on | "string" | hex_string ); ]
      [ rundir "string"; ]
      [ pidfile "string"; ]
      [ workers integer; ]
      [ background-workers integer; ]
      [ asynchronous-start ( on | off ); ]
      [ user string[.string]; ]
      [ max-conn-idle ( integer | integer(s | m | h | d); ) ]
      [ max-conn-handshake ( integer | integer(s | m | h | d); ) ]
      [ max-conn-reply ( integer | integer(s | m | h | d); ) ]
      [ max-tcp-clients integer; ]
      [ transfers integer; ]
      [ rate-limit integer; ]
      [ rate-limit-size integer; ]
      [ rate-limit-slip integer; ]
      [ max-udp-payload integer; ]
    }

.. _system Statement Definition and Usage:

``system`` Statement Definition and Usage
-----------------------------------------

.. _identity:

identity
^^^^^^^^

Identity of the server returned in a response for the query for TXT
record ``id.server.`` or ``hostname.bind.`` in the CHAOS class (see
`RFC\ 4892 <http://tools.ietf.org/html/rfc4892>`_).

If not specified or empty, the server returns REFUSED status code.  If
a boolean value of ``on`` is used, FQDN hostname is used as a default.

::

    system {
      identity "ns01.example.com";
      identity on;
    }

.. _version:

version
^^^^^^^

Version of the server software returned in a response for the query
for TXT record ``version.server.`` or ``version.bind.`` in the CHAOS
class (see `RFC\ 4892 <http://tools.ietf.org/html/rfc4892>`_).

Option allows a boolean value ``on|off``, if ``on``, automatic version
string is set as a default.  If not specified or empty, the server
returns REFUSED status code.

::

    system {
      version "Knot DNS 1.3.0";
      version on; # Reports current version
    }

.. _nsid:

nsid
^^^^

DNS Name Server Identifier (see `RFC\ 5001 <http://tools.ietf.org/html/rfc5001>`_).

Use a string format "text" or a hexstring (e.g.  0x01ab00) If a
boolean value of ``on`` is used, FQDN hostname is used as a default.

::

    system {
      nsid 0x00cafe;
      nsid "cafe";
      nsid on;
    }

.. _rundir:

rundir
^^^^^^

Path for storing run-time data, for example PID file and unix sockets.
Default value: ``${localstatedir}/run/knot``, configured with
``--with-rundir=path``

::

    system {
      rundir "/var/run/knot";
    }

.. _pidfile:

pidfile
^^^^^^^

Specifies a custom PID file location.

Default value: ``knot.pid`` in ``rundir`` directory.

::

    system {
      pidfile "/var/run/knot/knot_dmz.pid";
    }

.. _workers:

workers
^^^^^^^

Number of workers (threads) per server interface.  This option is used
to force number of threads used per interface.

Default value: unset (auto-estimates optimal value from the number of
online CPUs)

::

    system {
      workers 16;
    }

.. _background-workers:

background-workers
^^^^^^^^^^^^^^^^^^
This option is used to set number of threads used to execute background
operations (e.g., zone loading, zone signing, XFR zone updates, ...).

Default value: unset (auto-estimates optimal value for the number of online CPUs)

::

    system {
      background-workers 4;
    }


.. _asynchronous-start:

asynchronous-start
^^^^^^^^^^^^^^^^^^

When asynchronous startup is enabled, server doesn't wait for the zones to be
loaded, and starts responding immediately with SERVFAIL answers until the zone
loads. This may be useful in some scenarios, but it is disabled by default.

Default value: ``off`` (wait for zones to be loaded before answering)

::

    system {
      asynchronous-start off;
    }

.. _user:

user
^^^^

System ``user`` or ``user``.``group`` under which the Knot DNS is run
after starting and binding to interfaces.  Linux capabilities
(:ref:`Required libraries`) are employed if supported and this
configuration option is set.

Default value: ``root.root``

::

    system {
      user knot.knot;
    }

.. _max-conn-idle:

max-conn-idle
^^^^^^^^^^^^^

Maximum idle time between requests on a TCP connection.  This also
limits receiving of a single query, each query must be received in
this time limit.

Default value: ``20``

::

    system {
      max-conn-idle 20;
    }

.. _max-conn-handshake:

max-conn-handshake
^^^^^^^^^^^^^^^^^^

Maximum time between newly accepted TCP connection and first query.
This is useful to disconnect inactive connections faster, than
connection that already made at least 1 meaningful query.

Default value: ``5``

::

    system {
      max-conn-handshake 5;
    }

.. _max-conn-reply:

max-conn-reply
^^^^^^^^^^^^^^

Maximum time to wait for a reply to an issued SOA query.

Default value: ``10``

::

    system {
      max-conn-reply 10;
    }

.. _max-tcp-clients:

max-tcp-clients
^^^^^^^^^^^^^^^

Maximum number of TCP clients connected in parallel, set this below file descriptor limit to avoid resource exhaustion.

Default value: ``100``

::

    system {
      max-tcp-clients 100;
    }

.. _transfers:

transfers
^^^^^^^^^

Maximum parallel transfers, including pending SOA queries.  Lowest
possible number is the number of CPUs.

Default value: ``10``

::

    system {
      transfers 10;
    }

.. _rate-limit:

rate-limit
^^^^^^^^^^

Rate limiting is based on the token bucket scheme. A rate basically
represents a number of tokens available each second. Each response is
processed and classified (based on several discriminators, e.g.
source netblock, query type, zone name, rcode, etc.). Classified responses are
then hashed and assigned to a bucket containing number of available
tokens, timestamp and metadata. When available tokens are exhausted,
response is dropped or sent as truncated (see :ref:`rate-limit-slip`).
Number of available tokens is recalculated each second.

Default value: ``0`` (disabled)

::

    system {
      rate-limit 0;
    }

.. _rate-limit-size:

rate-limit-size
^^^^^^^^^^^^^^^

Size of the hash table in a number of buckets. The larger the hash table, the lesser
the probability of a hash collision, but at the expense of additional memory costs.
Each bucket is estimated roughly to 32 bytes. The size should be selected as
a reasonably large prime due to better hash function distribution properties.
Hash table is internally chained and works well up to a fill rate of 90 %, general
rule of thumb is to select a prime near 1.2 * maximum_qps.

Default value: ``393241``

::

    system {
      rate-limit-size 393241;
    }

.. _rate-limit-slip:

rate-limit-slip
^^^^^^^^^^^^^^^
As attacks using DNS/UDP are usually based on a forged source address,
an attacker could deny services to the victim's netblock if all
responses would be completely blocked. The idea behind SLIP mechanism
is to send each N\ :sup:`th` response as truncated, thus allowing client to
reconnect via TCP for at least some degree of service. It is worth
noting, that some responses can't be truncated (e.g. SERVFAIL).

- Setting the value to **0** will cause that all rate-limited responses will
  be dropped. The outbound bandwidth and packet rate will be strictly capped
  by the :ref:`rate-limit` option. All legitimate requestors affected
  by the limit will face denial of service and will observe excessive timeouts.
  Therefore this setting is not recommended.

- Setting the value to **1** will cause that all rate-limited responses will
  be sent as truncated. The amplification factor of the attack will be reduced,
  but the outbound data bandwidth won't be lower than the incoming bandwidth.
  Also the outbound packet rate will be the same as without RRL.

- Setting the value to **2** will cause that half of the rate-limited responses
  will be dropped, the other half will be sent as truncated. With this
  configuration, both outbound bandwidth and packet rate will be lower than the
  inbound. On the other hand, the dropped responses enlarge the time window
  for possible cache poisoning attack on the resolver.

- Setting the value to anything **larger than 2** will keep on decreasing
  the outgoing rate-limited bandwidth, packet rate, and chances to notify
  legitimate requestors to reconnect using TCP. These attributes are inversely
  proportional to the configured value. Setting the value high is not advisable.

Default value: ``1``

::

    system {
      rate-limit-slip 1;
    }

.. _max-udp-payload:

max-udp-payload
^^^^^^^^^^^^^^^

Maximum EDNS0 UDP payload size.

Default value: ``4096``

::

    system {
      max-udp-payload 4096;
    }

.. _system Example:

system Example
--------------

.. parsed-literal ::

    system {
      identity "Knot DNS |version|";
      version "|version|";
      nsid    "amaterasu";
      rundir "/var/run/knot";
      workers 16;
      user knot.knot;
      max-udp-payload 4096;
    }

.. _keys:

``keys`` Statement
==================

The ``keys`` statement sets up the TSIG keys used to authenticate
zone transfers.

.. _keys Syntax:

keys Syntax
-----------

::

    keys {
      key_id algorithm "string";
      [ key_id algorithm "string"; ... ]
    }

.. _keys Statement Definition and Usage:

Statement Definition and Usage
------------------------------

.. _key_id:

``key_id`` Statement
^^^^^^^^^^^^^^^^^^^^

The ``key_id`` statement defines a secret shared key for use with
TSIG.  It consists of its ``name``, ``algorithm`` and ``key``
contents.

Supported algoritms:

* hmac-md5
* hmac-sha1
* hmac-sha224
* hmac-sha256
* hmac-sha384
* hmac-sha512

You need to use bind or ldns utils to generate TSIG keys.
Unfortunately, Knot DNS does not have any own generation utilities
yet.

::

    $ dnssec-keygen -a HMAC-SHA256 -b 256 -n HOST foobar.example.com
    Kfoobar.example.com.+163+21239
    $ cat Kfoobar.example.com.+163+21239.key
    foobar.example.com.  ( IN KEY 512 3 163
                          rqv2WRyDgIUaHcJi03Zssor9jtG1kOpb3dPywxZfTeo= )

Key generated in previous paragraph would be written as::

    keys {
      foobar.example.com.  hmac-sha256
      "rqv2WRyDgIUaHcJi03Zssor9jtG1kOpb3dPywxZfTeo=";
    }

.. _keys Example:

keys Example
------------

::

    keys {
      key0.server0 hmac-md5 "Wg==";
      foobar.example.com.  hmac-sha256 "RQ==";
    }

.. _interfaces:

``interfaces`` Statement
========================

The ``interfaces`` statement contains IP interfaces where Knot DNS
listens for incoming queries.

.. _interfaces Syntax:

``interfaces`` Syntax
---------------------

::

    interfaces {
      interface_id
        ( ip_address[@port_number] |
          { address ip_address; [ port port_number; ] @} )
      [ interface_id ...; ...; ]
    }

.. _interfaces Statement Definition and Usage:

``interfaces`` Statement Definition and Usage
---------------------------------------------

.. _interface_id:

``interface_id``
^^^^^^^^^^^^^^^^

The ``interface_id`` is a textual identifier of an IP interface, which
consists of an IP address and a port.

The definition of an interface can be written in long or a short form
and it always contains IP (IPv4 or IPv6) address.

.. _interfaces Example:

``interfaces`` Example
----------------------

Long form::

    interfaces {
      my_ip {
        address 192.0.2.1;
        port 53;
      }
    }

Short form::

    interfaces {
      my_second_ip { address 198.51.100.1@53; }
    }

Short form without port (defaults to 53)::

    interfaces {
      my_third_ip { address 203.0.113.1; }
    }

.. _remotes:

``remotes`` Statement
=====================

The ``remotes`` statement sets up all remote servers for zone
transfers.  Knot DNS does not distinguish between client or server in
this section.  Role of the server is determined at the time of its
usage in the ``zones`` section.  One server may act as a client for
one zone (e.g.  downloading the updates) and as a master server for a
different zone.

.. _remotes Syntax:

``remotes`` Syntax
------------------

::

    remotes {
      remote_id
        ( ip_address[@port_number] |
          {   address ip_address;
             [ port port_number; ]
             [ key key_id; ]
             [ via [ interface_id | ip_address ]; ]
          }
        )
      [ remote_id ...; ...; ]
    }

.. _remotes Statement Definition and Grammar:

``remotes`` Statement Definition and Grammar
--------------------------------------------

.. _remote_id:

``remote_id``
^^^^^^^^^^^^^

``remote_id`` contains a symbolic name for a remote server.

.. _address:

``address``
^^^^^^^^^^^

``address`` sets an IPv4 or an IPv6 address for this particular
``remote``.

.. _port:

``port``
^^^^^^^^

``port`` section contains a port number for the current ``remote``.
This section is optional with default port set to 53.

.. _key:

``key``
^^^^^^^

``key`` section contains a key associated with this ``remote``.  This
section is optional.

.. _via:

via
^^^

``via`` section specifies which interface will be used to communicate
with this ``remote``.  This section is optional.

.. _remotes Example:

``remotes`` Example
-------------------

::

    remotes {
      # Long form:
      server0 {
        address 127.0.0.1;
        port 53531;
        key key0.server0;
        via ipv4;             # reference to interface named ipv4
        # via 82.35.64.59;    # direct IPv4
        # via [::cafe];       # direct IPv6
      }

      # Short form:
      server1 {
        address 127.0.0.1@53001;
      }
    }

.. _groups:

``groups`` Statement
====================

The ``groups`` statement is used to create groups of remote machines
defined in :ref:`remotes` statement.  The group can substitute multiple
machines specification anywhere in the configuration where the list of
remotes is allowed to be used (namely ``allow`` in :ref:`control`
section and ACLs in :ref:`zones` section).

The remotes definitions must exist prior to using them in group
definitions.  One remote can be a member of multiple groups.

.. _groups Syntax:

``groups`` Syntax
-----------------

::

    groups {
      group_id { remote_id [ , ... ] }
      [ ... ]
    }

.. _groups Statement Definition and Grammar:

``groups`` Statement Definition and Grammar
-------------------------------------------

.. _group_id:

``group_id``
^^^^^^^^^^^^

``group_id`` contains a symbolic name for a group of remotes.

.. _groups-remote_id:

``remote_id``
^^^^^^^^^^^^^

``remote_id`` contains a symbolic name for a remote server as
specified in :ref:`remotes` section.

.. _groups Example:

``groups`` Example
------------------

::

    remotes {
      ctl {
        # ...
      }
      alice {
        # ...
      }
      bob {
        # ...
      }
    }

    groups {
      admins { alice, bob }
    }

    # example usage:
    control {
      # ...
      allow ctl, admins;
    }

.. _control:

``control`` Statement
=====================

The ``control`` statement specifies on which interface to listen for
remote control commands.  Caution: The control protocol is not
encrypted, and susceptible to replay attack in a short timeframe until
message digest expires, for that reason, it is recommended to use
default UNIX sockets.

.. _control Syntax:

``control`` Syntax
------------------

::

    control {
      [ listen-on {
        ( address ip_address[@port_number] |
          { address ip_address; [ port port_number; ] } )
      } ]
      [ allow remote_id [, remote_id, ... ]; ]
    }

.. _control Statement Definition and Grammar:

``control`` Statement Definition and Grammar
--------------------------------------------

Control interface ``listen-on`` either defines a UNIX socket or an
IPv4/IPv6 ``interface`` definition as in :ref:`interfaces`.  Default
port for IPv4/v6 control interface is ``5533``, however UNIX socket is
preferred.  UNIX socket address is relative to ``rundir`` if not
specified as an absolute path.  Without any configuration, the socket
will be created in ``rundir/knot.sock``.

.. _control Examples:

``control`` Examples
--------------------


UNIX socket example::

    control {
            listen-on "/var/run/knot/knot.sock";
    }

IPv4 socket example::

    keys {
            knotc-key hmac-md5 "Wg==";
    }
    remotes {
            ctl { address 127.0.0.1; key knotc-key; }
    }
    control {
            listen-on { address 127.0.0.1; }
            allow ctl;
    }

.. _zones:

``zones`` Statement
===================

The ``zones`` statement contains definition of zones served by Knot DNS.

.. _zones Syntax:

``zones`` Syntax
----------------

::

    zones {
      [ zone_options ]
      [ timer-db "string"; ]
      zone_id {
        file "string";
        [ xfr-in remote_id [, remote_id, ... ]; ]
        [ xfr-out remote_id [, remote_id, ... ]; ]
        [ notify-in remote_id [, remote_id, ... ]; ]
        [ notify-out remote_id [, remote_id, ... ]; ]
        [ update-in remote_id [, remote_id, ... ]; ]
        [ zone_options ]
      }
    }

    zone_options :=
      [ storage "string"; ]
      [ semantic-checks boolean; ]
      [ ixfr-from-differences boolean; ]
      [ disable-any boolean; ]
      [ notify-timeout ( integer | integer(s | m | h | d); ) ]
      [ notify-retries integer; ]
      [ zonefile-sync ( integer | integer(s | m | h | d); ) ]
      [ ixfr-fslimit ( integer | integer(k | M | G) ); ]
      [ ixfr-from-differences boolean; ]
      [ max-zone-size ( integer | integer(k | M | G) ); ]
      [ dnssec-keydir "string"; ]
      [ dnssec-enable ( on | off ); ]
      [ signature-lifetime ( integer | integer(s | m | h | d); ) ]
      [ serial-policy ( increment | unixtime ); ]
      [ request-edns-option integer ("string" | hex_string ); ]
      [ query_module { module_name "string"; [ module_name "string"; ... ] } ]

.. _zones Statement Definition and Grammar:

``zones`` Statement Definition and Grammar
------------------------------------------

.. _zone_id:

``zone_id``
^^^^^^^^^^^

``zone_id`` is a zone origin, and as such is a domain name that may or
may not end with a ".".  If no $ORIGIN directive is found inside
actual zone file, this domain name will be used in place of "@".  SOA
record in the zone must have this name as its owner.

.. _file:

``file``
^^^^^^^^

The ``file`` statement defines a path to the zone file.  You can
either use an absolute path or a relative path.  In that case, the
zone file path will be relative to the ``storage`` directory
(:ref:`storage`).

.. _xfr-in:

``xfr-in``
^^^^^^^^^^

In ``xfr-in`` statement user specifies which remotes will be permitted
to perform a zone transfer to update the zone.  Remotes are defined in
``remotes`` section of configuration file (:ref:`remotes`).

.. _xfr-out:

``xfr-out``
^^^^^^^^^^^

In ``xfr-out`` statement user specifies which remotes will be
permitted to obtain zone's contents via zone transfer.  Remotes are
defined in ``remotes`` section of configuration file
(:ref:`remotes`).

.. _notify-in:

``notify-in``
^^^^^^^^^^^^^

``notify-in`` defines which remotes will be permitted to send NOTIFY
for this particular zone.  Remotes are defined in ``remotes`` section
of configuration file (:ref:`remotes`).

.. _notify-out:

``notify-out``
^^^^^^^^^^^^^^

``notify-out`` defines to which remotes will your server send NOTIFYs
about this particular zone.  Remotes are defined in ``remotes``
section of configuration file (:ref:`remotes`).

.. _update-in:

``update-in``
^^^^^^^^^^^^^

In ``update-in`` statement user specifies which remotes will be
permitted to perform a DNS UPDATE.  Remotes are defined in ``remotes``
section of configuration file (:ref:`remotes`).

.. _query_module :

``query_module``
^^^^^^^^^^^^^^^^

Statement ``query_module`` takes a list of ``module_name
"config_string"`` query modules separated by semicolon.

.. _storage:

``storage``
^^^^^^^^^^^

Data directory for zones.  It is used to store zone files and journal
files.

Value of ``storage`` set in ``zone`` section is relative to
``storage`` in ``zones`` section.

Default value (in ``zones`` section): ``${localstatedir}/lib/knot``,
configured with ``--with-storage=path``

Default value (in ``zone`` config): inherited from ``zones`` section

::

    zones {
      storage "/var/lib/knot";
      example.com {
        storage "com";
        file "example.com"; # /var/lib/knot/com/example.com
      }
    }

.. _semantic-checks:

``semantic-checks``
^^^^^^^^^^^^^^^^^^^

``semantic-checks`` statement turns on optional semantic checks for
this particular zone.  See :ref:`zones List of zone semantic checks` for
more information.

Possible values are ``on`` and ``off``.  Most checks are disabled by
default.

.. _ixfr-from-differences:

``ixfr-from-differences``
^^^^^^^^^^^^^^^^^^^^^^^^^

Option ``ixfr-from-differences`` is only relevant if you are running
Knot DNS as a master for this zone.  By turning the feature on you
tell Knot to create differences from changes you made to a zone file
upon server reload.  See :ref:`Controlling running daemon` for more
information.

Possible values are ``on`` and ``off``.  Disabled by default.

.. _zone_max_zone_size:

max-zone-size
----------------

Maximum size of the zone. The size is measured as size of the zone records
in wire format without compression. The limit is enforced for incoming zone
transfers and dynamic updates.

For incremental transfers (IXFR), the effective limit for the total size of
the records in the transfer is twice the configured value. However the final
size of the zone must satisfy the configured value.

*Default:* unlimited

.. _disable-any:

``disable-any``
^^^^^^^^^^^^^^^

If you enable ``disable-any``, all authoritative ANY queries sent over
UDP will be answered with an empty response and with the TC bit set.
Use to minimize the risk of DNS reflection attack.  Disabled by default.

.. _notify-timeout:

``notify-timeout``
^^^^^^^^^^^^^^^^^^

``notify-timeout`` in seconds specifies how long will server wait for
NOTIFY response.  Possible values are 1 to INT_MAX.  By default, this
value is set to 60 seconds.

.. _notify-retries:

``notify-retries``
^^^^^^^^^^^^^^^^^^

``notify-retries`` tells the server how many times it can retry to
send a NOTIFY.  Possible values are 1 to INT_MAX and default value
is 5.

.. _zonefile-sync:

``zonefile-sync``
^^^^^^^^^^^^^^^^^

``zonefile-sync`` specifies a time in seconds after which current zone
in memory will be synced to zone file on the disk (as set in
:ref:`file`).  Knot DNS will serve the latest zone even after restart,
but zone file on a disk will only be synced after ``zonefile-sync``
time has expired (or synced manually via ``knotc flush`` - see
:ref:`Running Knot DNS`).  This is applicable when the zone is updated
via IXFR, DDNS or automatic DNSSEC signing.  Possible values are 0 to
INT_MAX, optionally suffixed by unit size (s/m/h/d) - *1s* is one
second, *1m* one minute, *1h* one hour and *1d* one day
with default value set to *0s*.

*Important note:* If you are serving large zones with frequent
updates where the immediate sync to zone file is not desirable, set
this value in the configuration file to other value.

.. _ixfr-fslimit:

``ixfr-fslimit``
^^^^^^^^^^^^^^^^

``ixfr-fslimit`` sets a maximum file size for zone's journal in bytes.
Possible values are 1 to INT_MAX, with optional suffixes k, m and G.
I.e.  *1k*, *1m* and *1G* with default value not being set, meaning
that journal file can grow without limitations.

.. _dnssec-keydir:

``dnssec-keydir``
^^^^^^^^^^^^^^^^^

Location of DNSSEC signing keys, relative to ``storage``.

Default value: not set

.. _dnssec-enable:

``dnssec-enable``
^^^^^^^^^^^^^^^^^

PREVIEW: Enable automatic DNSSEC signing for the zone.

Default value (in ``zones`` section): ``off``

Default value (in ``zone`` config): inherited from ``zones`` section

.. _signature-lifetime:

``signature-lifetime``
^^^^^^^^^^^^^^^^^^^^^^

Specifies how long should the automatically generated DNSSEC signatures be valid.
Expiration will thus be set as current time (in the moment of signing)
+ ``signature-lifetime``.  Possible values are from 10801 to INT_MAX.
The signatures are refreshed one tenth of the signature lifetime
before the signature expiration (i.e., 3 days before the expiration
with the default value).  For information about zone expiration date,
invoke the ``knotc zonestatus`` command.

Default value: ``30d`` (``2592000``)

.. _serial-policy:

``serial-policy``
^^^^^^^^^^^^^^^^^

Specifies how the zone serial is updated after DDNS (dynamic update)
and automatic DNSSEC signing.  If the serial is changed by the dynamic
update, no change is made.

* ``increment`` - After update or signing, the serial is automatically
  incremented (according to serial number arithmetic).
* ``unixtime`` - After update or signing, serial is set to the current
  unix time.

*Warning:* If your serial was in other than unix time format, be
careful with transition to unix time.  It may happen that the new
serial will be 'lower' than the old one.  If this is the case, the
transition should be done by hand (see `RFC\ 1982
<https://tools.ietf.org/html/rfc1982>`_).

Default value: ``increment``

.. _request-edns-option:

``request-edns-option``
^^^^^^^^^^^^^^^^^^^^^^^

An arbitrary EDNS0 option which is included into a server request (AXFR, IXFR,
SOA, or NOTIFY). The first value is option code and the second value is option
data in the form of a text or hexadecimal string.

Default value: not set

.. _timer-db:

``timer-db``
^^^^^^^^^^^^

Specifies a path of the persistent timer database. The path can be specified
as a relative path to the storage directory (:ref:`storage`).

Default value: ``"timers"``

.. _zones Example:

``zones`` Example
-----------------

::

    zones {

      # Shared options for all listed zones
      storage "/var/lib/knot";
      ixfr-from-differences off;
      semantic-checks off;
      disable-any off;
      notify-timeout 60;
      notify-retries 5;
      zonefile-sync 0;
      ixfr-fslimit 1G;
      dnssec-enable on;
      dnssec-keydir "keys";
      signature-lifetime 60d;
      serial-policy increment;
      example.com {
        storage "samples";
        file "example.com.zone";
        ixfr-from-differences off;
        disable-any off;
        semantic-checks on;
        notify-timeout 60;
        notify-retries 5;
        zonefile-sync 0;
        dnssec-keydir "keys";
        dnssec-enable off;
        signature-lifetime 30d;
        serial-policy increment;
        xfr-in server0;
        xfr-out server0, server1;
        notify-in server0;
        notify-out server0, server1;
      }
    }

.. _zones List of zone semantic checks:

``zones`` List of zone semantic checks
--------------------------------------

The ``semantic-checks`` statement turns on extra zone file semantic
checks.  Several checks are enabled by default and cannot be turned
off.  If an error is found using these mandatory checks, the zone file
will not be loaded.  Upon loading a zone file, occurred errors and
counts of their occurrence will be logged to *stderr*.  These
checks are the following:

* An extra record together with CNAME record (except for RRSIG and DS)
* CNAME link chain length greater than 10 (including infinite cycles)
* DNAME and CNAME records under the same owner (RFC 2672)
* CNAME and DNAME wildcards pointing to themselves
* SOA record missing in the zone (RFC 1034)
* DNAME records having records under it (DNAME children) (RFC 2672)

Following checks have to be turned on using ``semantic-checks`` and a
zone containing following errors will be loaded even upon discovering
an error:

- Missing NS record at the zone apex
- Missing glue A or AAAA records
- Broken or non-cyclic NSEC(3) chain
- Wrong NSEC(3) type bitmap
- Multiple NSEC records at the same node
- Missing NSEC records at authoritative nodes
- Extra record types under same name as NSEC3 record (this is
  RFC-valid, but Knot will not serve such a zone correctly)
- NSEC3-unsecured delegation that is not part of Opt-out span
- Wrong original TTL value in NSEC3 records
- Wrong RDATA TTL value in RRSIG record
- Signer name in RRSIG RR not the same as in DNSKEY
- Signed RRSIG
- Not all RRs in node are signed
- Wrong key flags or wrong key in RRSIG record (not the same as ZSK)

.. _log:

``log`` Statement
=================

.. _log Syntax:

``log`` Syntax
--------------

::

    log {
      [ log_name {
        [ category severity; ]
      } ]
      [ log_file filename {
        [ category severity; ]
      } ]
    }

.. _log Statement Definition and Grammar:

``log`` Statement Definition and Grammar
----------------------------------------

The ``log`` statement configures logging output of Knot DNS.  You can
configure Knot DNS to log into file or system log.  There are several
logging categories to choose from.  Each log message has its severity
and user can configure severities for each log destination.

In case of missing log section, severities from ``warning`` and more
serious will be logged to both ``stderr`` and ``syslog``.  The
``info`` and ``notice`` severities will be logged to the ``stdout``.

.. _log_name:

``log_name``
^^^^^^^^^^^^

``log_name`` should be replaced with one of 3 symbolic log names:

* ``stdout`` - logging to standard output
* ``stderr`` - logging to standard error output
* ``syslog`` - logging to syslog (or systemd journal, if systemd support is enabled)

.. _category:

``category``
^^^^^^^^^^^^

Knot DNS allows user to choose from these logging categories:

* ``server`` - Messages related to general operation of the server.
* ``zone`` - Messages related to zones, zone parsing and loading.
* ``any`` - All categories.

If systemd support is enabled, the log messages in the `zone` category are
given the `ZONE` field containing a name of the zone. The field can be used
to filter the log entries in the journal.

.. _severity:

``severity``
^^^^^^^^^^^^

Knot DNS has the following logging severities:

* ``debug`` - Debug messages, must be turned on at compile time (:ref:`Enabling debug messages in server`).
* ``info`` - Informational message.
* ``notice`` - Server notices and hints.
* ``warning`` - Warnings that might require user action.
* ``error`` - Recoverable error.  Action should be taken.
* ``critical`` - Non-recoverable error resulting in server shutdown.

Each severity level includes all more serious levels, i.e. ``warning`` severity
also includes ``error`` and ``critical`` severities.

.. _log_file:

``log_file``
^^^^^^^^^^^^

``log_file`` is either absolute or relative path to file user wants to
log to.  See following example for clarification.

.. _log Example:

log Example
-----------

::

    log {

      syslog {
        any error;
        zone warning, notice;
        server info;
      }

      stderr {
        any error, warning;
      }

      file "/tmp/knot-sample/knotd.debug" {
        server debug;
      }
    }

.. _include:

``include`` Statement
=====================

The ``include`` statement is a special statement which can be used
almost anywhere on any level in the configuration file.  It allows
inclusion of another file or all files in the given directory.

The path of the included file can be either absolute or relative to a
configuration file currently being processed.

.. _include Syntax:

``include`` Syntax
------------------

::

    include "filename";
    include "dirname";

.. _include Examples:

``include`` Examples
--------------------

::

    include "keys.conf";

    remotes {
      ctl {
        address 127.0.0.1;
        key knotc-key;
      }
      include "remotes.conf";
    }

    include "zones";
