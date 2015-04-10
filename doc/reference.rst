.. meta::
   :description: reStructuredText plaintext markup language

.. _Configuration Reference:

***********************
Configuration Reference
***********************

.. _Description:

Description
===========

Configuration file for Knot DNS uses simplified YAML format. Simplified means
that not all features are supported.

For the configuration items description, there are some symbol with the
folowing meaning:

- *INT* - Integer
- *STR* - Textual string
- *HEXSTR* - Hexadecimal string (with ``0x`` prefix)
- *BOOL* - Boolean value (``on`` or ``off``)
- *TIME* - Number of seconds, integer with possible time mutliplier suffix
  (``s`` ~ 1, ``m`` ~ 60, ``h`` ~ 3600 or ``d`` ~ 24 * 3600)
- *SIZE* - Number of bytes, integer with possible size multiplier suffix
  (``B`` ~ 1, ``K`` ~ 1024, ``M`` ~ 1024^2 or ``G`` ~ 1024^3)
- *BASE64* - Base64 encoded string
- *ADDR* - IPv4 or IPv6 address
- *DNAME* - Domain name
- ... - Multi-valued item, order of the values is preserved
- [ ] - Optional value
- \| - Choice

There are 8 main sections (``server``, ``key``, ``acl``, ``control``,
``remote``, ``template``, ``zone`` and ``log``) and module sections with
``mod-`` prefix . Most of the sections (excluding ``server`` and
``control``) are sequences of settings blocks. Each settings block
begins with a unique identifier, which can be used as a reference from other
sections (such identifier must be defined in advance).

Multi-valued item can be specified either as a YAML sequence [val1, val2, ...]
or as more single-valued items each on the extra line.

If an item value contains spaces or other special characters, it is necessary
to double quote such value with ``"`` ``"``.

.. _Comments:

Comments
========

A comment begins with a ``#`` character and is ignored during the processing.
Also each configuration section or sequence block allows to specify permanent
comment using ``comment`` item which is stored in the server beside the
configuration.

.. _Includes:

Includes
========

Another configuration file or all configuration files in a directory can be
included at the top level in the current file. If the file or directory path
is not absolute, then it is relative to the current file directory.

::

 include: STR

.. _Server section:

Server section
==============

General options related to the server.

::

 server:
     identity: [STR]
     version: [STR]
     nsid: [STR|HEXSTR]
     rundir: STR
     user: STR[:STR]
     pidfile: STR
     workers: INT
     background-workers: INT
     asynchronous-start: BOOL
     max-conn-idle: TIME
     max-conn-handshake: TIME
     max-conn-reply: TIME
     max-tcp-clients: INT
     max-udp-payload: SIZE
     transfers: INT
     rate-limit: INT
     rate-limit-slip: INT
     rate-limit-size: INT
     listen: ADDR[@INT] ...

.. _server_identity:

identity
--------

An identity of the server returned in the response for the query for TXT
record ``id.server.`` or ``hostname.bind.`` in the CHAOS class (see RFC 4892).
If empty, FQDN hostname is used.

Default: disabled

.. _server_version:

version
-------

A version of the server software returned in the response for the query
for TXT record ``version.server.`` or ``version.bind.`` in the CHAOS
class (see RFC 4892). If empty, automatic version is used.

Default: disabled

.. _server_nsid:

nsid
----

A DNS name server identifier (see RFC 5001). If empty, FQDN hostname is used.

Default: disabled

.. _server_rundir:

rundir
------

A path for storing run-time data (PID file, unix sockets, etc.).

Default: ``${localstatedir}/run/knot`` (configured with ``--with-rundir=path``)

.. _server_user:

user
----

A system user with an optional system group (*user*:*group*) under which the
server is run after starting and binding to interfaces. Linux capabilities
are employed if supported.

Default: root:root

.. _server_pidfile:

pidfile
-------

A PID file location.

Default: :ref:`rundir<server_rundir>`/knot.pid

.. _server_workers:

workers
-------

A number of quering workers (threads) per server interface.

Default: auto-estimated optimal value based on the number of online CPUs

.. _server_background-workers:

background-workers
------------------

A number of workers (threads) used to execute background operations (zone
loading, zone updates, etc.).

Default: auto-estimated optimal value based on the number of online CPUs

.. _server_asynchronous-start:

asynchronous-start
------------------

If enabled, server doesn't wait for the zones to be loaded and starts
responding immediately with SERVFAIL answers until the zone loads.

Default: off

.. _server_max-conn-idle:

max-conn-idle
-------------

Maximum idle time between requests on a TCP connection. This also limits
receiving of a single query, each query must be received in this time limit.

Default: 20

.. _server_max-conn-handshake:

max-conn-handshake
------------------

Maximum time between newly accepted TCP connection and the first query.
This is useful to disconnect inactive connections faster than connections
that already made at least 1 meaningful query.

Default: 5

.. _server_max-conn-reply:

max-conn-reply
--------------

Maximum time to wait for a reply to an issued SOA query.

Default: 10

.. _server_max-tcp-clients:

max-tcp-clients
---------------

A maximum number of TCP clients connected in parallel, set this below the file
descriptor limit to avoid resource exhaustion.

Default: 100

.. _server_transfers:

transfers
---------

A maximum number of parallel transfers, including pending SOA queries. The
minimum value is determined by the number of CPUs.

Default: 10

.. _server_rate-limit:

rate-limit
----------

Rate limiting is based on the token bucket scheme. Rate basically
represents number of tokens available each second. Each response is
processed and classified (based on several discriminators, e.g.
source netblock, qtype, name, rcode, etc.). Classified responses are
then hashed and assigned to a bucket containing number of available
tokens, timestamp and metadata. When available tokens are exhausted,
response is rejected or enters :ref:`SLIP<server_rate-limit-slip>`
(server responds with a truncated response). Number of available tokens
is recalculated each second.

Default: 0 (disabled)

.. _server_rate-limit-size:

rate-limit-size
---------------

Size of hashtable buckets. The larger the hashtable, the lesser probability
of a hash collision, but at the expense of additional memory costs. Each bucket
is estimated roughly to 32 bytes. Size should be selected as a reasonably large
prime due to the better hash function distribution properties. Hash table is
internally chained and works well up to a fill rate of 90 %, general
rule of thumb is to select a prime near 1.2 * maximum_qps.

Default: 393241

.. _server_rate-limit-slip:

rate-limit-slip
---------------

As attacks using DNS/UDP are usually based on a forged source address,
an attacker could deny services to the victim netblock if all
responses would be completely blocked. The idea behind SLIP mechanism
is to send each Nth response as truncated, thus allowing client to
reconnect via TCP for at least some degree of service. It is worth
noting, that some responses can't be truncated (e.g. SERVFAIL).

It is advisable not to set the slip interval to a value larger than 2,
as too large slip value means more denial of service for legitimate
requestors, and introduces excessive timeouts during resolution.
On the other hand, slipping truncated answer gives the legitimate
requestors a chance to reconnect over TCP.

Default: 1

.. _server_max-udp-payload:

max-udp-payload
---------------

Maximum EDNS0 UDP payload size.

Default: 4096

.. _server_listen:

listen
------

One or more IP addresses where the server listens for incoming queries.
Optional port specification (default is 53) can be appended to each address
using ``@`` separator. Use ``0.0.0.0`` for all configured IPv4 addresses or
``::`` for all configured IPv6 addresses.

Default: empty

.. _Key section:

Key section
===========

Shared TSIG keys used to authenticate communication with the server.

::

 key:
   - id: DNAME
     algorithm: hmac-md5 | hmac-sha1 | hmac-sha224 | hmac-sha256 | hmac-sha384 | hmac-sha512
     secret: BASE64

.. _key_id:

id
--

A key name identifier.

.. _key_algorithm:

algorithm
---------

A key algorithm.

Default: empty

.. _key_secret:

secret
------

Shared key secret.

Default: empty

.. _ACL section:

ACL section
===========

Access control list rules definition.

::

 acl:
   - id: STR
     address: ADDR[/INT]
     key: key_id
     action: deny | xfer | notify | update | control ...

.. _acl_id:

id
--

An ACL rule identifier.

.. _acl_address:

address
-------

A single IP address or network subnet with the given prefix the query
must match.

Default: empty

.. _acl_key:

key
---

A :ref:`reference<key_id>` to the TSIG key the query must match.

Default: empty

.. _acl_action:

action
------

An ordered list of allowed actions.

Possible values:

- ``deny`` - Block the matching query
- ``xfer`` - Allow zone transfer
- ``notify`` - Allow incoming notify
- ``update`` - Allow zone updates
- ``control`` - Allow remote control

Default: deny

.. _Control section:

Control section
===============

Configuration of the server remote control.

Caution: The control protocol is not encrypted, and susceptible to replay
attacks in a short timeframe until message digest expires, for that reason,
it is recommended to use default UNIX socket.

::

 control:
     listen: ADDR[@INT]
     acl: acl_id ...

.. _control_listen:

listen
------

A UNIX socket path or IP address where the server listens for remote control
commands. Optional port specification (default is 5533) can be appended to the
address using ``@`` separator.

Default: :ref:`rundir<server_rundir>`/knot.sock

.. _control_acl:

acl
---

An ordered list of :ref:`references<acl_id>` to ACL rules allowing the remote
control.

Caution: This option has no effect with UNIX socket.

Default: empty

.. _Remote section:

Remote section
==============

Definition of remote servers for zone transfers or notifications.

::

 remote:
   - id: STR
     address: ADDR[@INT]
     via: ADDR[@INT]
     key: key_id

.. _remote_id:

id
--

A remote identifier.

.. _remote_address:

address
-------

A destination IP address of the remote server. Optional destination port
specification (default is 53) can be appended to the address using ``@``
separator.

Default: empty

.. _remote_via:

via
---

A source IP address which is used to communicate with the remote server.
Optional source port specification can be appended to the address using
``@`` separator.

Default: empty

.. _remote_key:

key
---

A :ref:`reference<key_id>` to the TSIG key which ise used to autenticate
the communication with the remote server.

Default: empty

.. _Template section:

Template section
================

A template is shareable zone settings which can be used for configuration of
many zones at one place. A special default template (with *default* identifier)
can be used for general quering configuration or as an implicit default
configuration if a zone doesn't have a teplate specified.

::

 template:
   - id: STR
     storage: STR
     master: remote_id ...
     notify: remote_id ...
     acl: acl_id ...
     semantic-checks: BOOL
     disable-any: BOOL
     notify-timeout: TIME
     notify-retries: INT
     zonefile-sync: TIME
     ixfr-from-differences: BOOL
     ixfr-fslimit: SIZE
     dnssec-enable: BOOL
     dnssec-keydir: STR
     signature-lifetime: TIME
     serial-policy: increment | unixtime
     module: STR/STR ...

.. _template_id:

id
--

A template identifier.

.. _template_storage:

storage
-------

A data directory for storing zone files, journal files and timers database.

Default: ``${localstatedir}/lib/knot`` (configured with ``--with-storage=path``)

.. _template_master:

master
------

An ordered list of :ref:`references<remote_id>` to zone master servers.

Default: empty

.. _template_notify:

notify
------

An ordered list of :ref:`references<remote_id>` to remotes to which notify
message is sent if the zone changes.

Default: empty

.. _template_acl:

acl
---

An ordered list of :ref:`references<acl_id>` to ACL rules which can allow
or disallow zone transfers, updates or incoming notifies.

Default: empty

.. _template_semantic-checks:

semantic-checks
---------------

If enabled, extra zone file semantic checks are turned on.

Several checks are enabled by default and cannot be turned off. An error in
mandatory checks causes zone not to be loaded. An error in extra checks is
logged only.

Mandatory checks:

- An extra record together with CNAME record (except for RRSIG and DS)
- CNAME link chain length greater than 10 (including infinite cycles)
- DNAME and CNAME records under the same owner (RFC 2672)
- CNAME and DNAME wildcards pointing to themselves
- SOA record missing in the zone (RFC 1034)
- DNAME records having records under it (DNAME children) (RFC 2672)

Extra checks:

- Missing NS record at the zone apex
- Missing glue A or AAAA records
- Broken or non-cyclic NSEC(3) chain
- Wrong NSEC(3) type bitmap
- Multiple NSEC records at the same node
- Missing NSEC records at authoritative nodes
- Extra record types under same name as NSEC3 record (this is RFC-valid, but
  Knot will not serve such a zone correctly)
- NSEC3-unsecured delegation that is not part of Opt-out span
- Wrong original TTL value in NSEC3 records
- Wrong RDATA TTL value in RRSIG record
- Signer name in RRSIG RR not the same as in DNSKEY
- Signed RRSIG
- Not all RRs in node are signed
- Wrong key flags or wrong key in RRSIG record (not the same as ZSK)

Default: off

.. _template_disable-any:

disable-any
-----------

If you enabled, all authoritative ANY queries sent over UDP will be answered
with an empty response and with the TC bit set. Use this option to minimize
the risk of DNS reflection attack.

Default: off

.. _template_notify-timeout:

notify-timeout
--------------

The time how long will server wait for a notify response.

Default: 60

.. _template_notify-retries:

notify-retries
--------------

The number of retries the server sends a notify message.

Default: 5

.. _template_zonefile-sync:

zonefile-sync
-------------

The time after which the current zone in memory will be synced to zone file
on the disk (see :ref:`file<zone_file>`). The server will serve the latest
zone even after restart using zone journal, but the zone file on the disk will
only be synced after ``zonefile-sync`` time has expired (or after manual zone
flush) This is applicable when the zone is updated via IXFR, DDNS or automatic
DNSSEC signing.

*Caution:* If you are serving large zones with frequent updates where
the immediate sync to zone file is not desirable, increase the default value.

Default: 0 (immediate)

.. _template_ixfr-from-differences:

ixfr-from-differences
---------------------

If enabled, the server creates zone differences from changes you made to the
zone file upon server reload. This option is only relevant if the server
is a master server for the zone.

Default: off

.. _template_ixfr-fslimit:

ixfr-fslimit
------------

Maximum zone journal file.

Default: unlimited

.. _template_dnssec-enable:

dnssec-enable
-------------

If enabled, automatic DNSSEC signing for the zone is turned on.

Default: off

.. _template_dnssec-keydir:

dnssec-keydir
-------------

A data directory for storing DNSSEC signing keys. Non absolute path is
relative to :ref:`storage<template_storage>`.

Default: :ref:`storage<template_storage>`/keys

.. _template_signature-lifetime:

signature-lifetime
------------------

The time how long the automatically generated DNSSEC signatures should be valid.
Expiration will thus be set as current time (in the moment of signing)
+ ``signature-lifetime``. The signatures are refreshed one tenth of the
signature lifetime before the signature expiration (i.e. 3 days before the
expiration with the default value). Minimum possible value is 10801.

Default: 30 * 24 * 3600

.. _template_serial-policy:

serial-policy
-------------

Specifies how the zone serial is updated after a dynamic update or
automatic DNSSEC signing. If the serial is changed by the dynamic update,
no change is made.

Possible values:

- ``increment`` - The serial is incremented according to serial number arithmetic
- ``unixtime`` - The serial is set to the current unix time

*Caution:* If your serial was in other than unix time format, be careful
with the transition to unix time.  It may happen that the new serial will
be \'lower\' than the old one. If this is the case, the transition should be
done by hand (see RFC 1982).

Default: increment

.. _template_module:

module
------

An ordered list of references to query modules in the form
*module_name/module_id*.

Default: empty

.. _Zone section:

Zone section
============

Definitions of zones served by the server.

Zone configuration is a superset of :ref:`template configuration<Template section>`,
so each zone configuration can contain all template configuration options which
may override possible template configuration.

::

 zone:
   - domain: DNAME
     file: STR
     template: template_id
     # All template options

.. _zone_domain:

domain
------

A zone name identifier.

.. _zone_file:

file
----

A path to the zone file. Non absolute path is relative to
:ref:`storage<template_storage>`.

Default: :ref:`storage<template_storage>`/``domain``.zone

.. _zone_template:

template
--------

A :ref:`reference<template_id>` to configuration template. If not specified
and *default* template exists, then the default template is used.

Default: empty

.. _Logging section:

Logging section
===============

Server can be configured to log to the standard output, standard error
output, syslog (or systemd journal if systemd is enabled) or into an arbitrary
file.

There are 6 logging severities:

- ``critical`` - Non-recoverable error resulting in server shutdown

- ``error`` - Recoverable error, action should be taken

- ``warning`` - Warning that might require user action

- ``notice`` - Server notice or hint

- ``info`` - Informational message

- ``debug`` - Debug messages (must be turned on at compile time)

In case of missing log section, ``warning`` or more serious messages
will be logged to both standard error output and syslog. The ``info`` and
``notice`` messages will be logged to standard output.

::

 log:
   - to: stdout | stderr | syslog | STR
     server: critical | error | warning | notice | info | debug
     zone: critical | error | warning | notice | info | debug
     any: critical | error | warning | notice | info | debug

.. _log_to:

to
--

A logging output.

Possible values:

- ``stdout`` - Standard output
- ``stderr`` - Standard error output
- ``syslog`` - Syslog
- *file_name* - File.

.. _log_server:

server
------

Minimum severity level for messages related to general operation of the server
that are logged.

Default: empty

.. _log_zone:

zone
----

Minimum severity level for messages related to zones that are logged.

Default: empty

.. _log_any:

any
---

Minimum severity level for all message types that are logged.

Default: empty

.. _Module dnstap:

Module dnstap
=============

Module dnstap allows query and response logging.

For all queries logging, use this module in the *default* template. For
zone-specific logging, use this module in the proper zone configuration.

::

 mod-dnstap:
   - id: STR
     sink: STR

.. _mod-dnstap_id:

id
--

A module identifier.

.. _mod-dnstap_sink:

sink
----

A sink path, which can either be a file or a UNIX socket prefixed with
``unix:``.

Default: empty

.. _Module synth-record:

Module synth-record
===================

This module is able to synthetise either forward or reverse records for the
given prefix and subnet.

::

 mod-synth-record:
   - id: STR
     type: forward | reverse
     prefix: STR
     zone: DNAME
     ttl: INT
     address: ADDR[/INT]

.. _mod-synth-record_id:

id
--

A module identifier.

.. _mod-synth-record_type:

type
----

The type of generated records.

Possible values:

- ``forward`` - Forward records
- ``reverse`` - Reverse records

Default: empty

.. _mod-synth-record_prefix:

prefix
------

A record owner prefix.

Caution: *prefix* doesn’t allow dots, address parts in the synthetic names are
separated with a dash.

Default: empty

.. _mod-synth-record_zone:

zone
----

A zone name suffix (only valid for :ref:`reverse type<mod-synth-record_type>`).

Default: empty

.. _mod-synth-record_ttl:

ttl
---

Time to live of the generated records.

Default: 3600

.. _mod-synth-record_address:

address
-------

A network subnet in the form of *address/prefix*.

Default: empty

.. _Module dnsproxy:

Module dnsproxy
===============

The module catches all unsatisfied queries and forwards them to the configured
server for resolution.

::

 mod-dnsproxy:
   - id: STR
     remote: ADDR[@INT]

.. _mod-dnsproxy_id:

id
--

A module identifier.

.. _mod-dnsproxy_remote:

remote
------

An IP address of the destination server. Optional port specification
(default is 53) can be appended to the address using ``@`` separator.

Default: empty

.. _Module rosedb:

Module rosedb
=============

The module provides a mean to override responses for certain queries before
the record is searched in the available zones.

::

 mod-rosedb:
   - id: STR
     dbdir: STR

.. _mod-rosedb_id:

id
--

A module identifier.

.. _mod-rosedb_dbdir:

dbdir
-----

A path to the directory where the database will is stored.

Default: empty
