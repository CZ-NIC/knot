.. highlight:: none
.. _Configuration Reference:

***********************
Configuration Reference
***********************

.. _Description:

Description
===========

Configuration files for Knot DNS use simplified YAML format. Simplified means
that not all of the features are supported.

For the description of configuration items, we have to declare a meaning of
the following symbols:

- *INT* – Integer
- *STR* – Textual string
- *HEXSTR* – Hexadecimal string (with ``0x`` prefix)
- *BOOL* – Boolean value (``on``/``off`` or ``true``/``false``)
- *TIME* – Number of seconds, an integer with possible time multiplier suffix
  (``s`` ~ 1, ``m`` ~ 60, ``h`` ~ 3600 or ``d`` ~ 24 * 3600)
- *SIZE* – Number of bytes, an integer with possible size multiplier suffix
  (``B`` ~ 1, ``K`` ~ 1024, ``M`` ~ 1024^2 or ``G`` ~ 1024^3)
- *BASE64* – Base64 encoded string
- *ADDR* – IPv4 or IPv6 address
- *DNAME* – Domain name
- ... – Multi-valued item, order of the values is preserved
- [ ] – Optional value
- \| – Choice

There are 11 main sections (``server``, ``control``, ``log``, ``statistics``,
``keystore``, ``policy``, ``key``, ``acl``, ``remote``, ``template``, and
``zone``) and module sections with the ``mod-`` prefix. Most of the sections
(excluding ``server``, ``control``, and ``statistics``) are sequences of
settings blocks. Each settings block begins with a unique identifier,
which can be used as a reference from other sections (such identifier
must be defined in advance).

A multi-valued item can be specified either as a YAML sequence::

 address: [10.0.0.1, 10.0.0.2]

or as more single-valued items each on an extra line::

 address: 10.0.0.1
 address: 10.0.0.2

If an item value contains spaces or other special characters, it is necessary
to enclose such value within double quotes ``"`` ``"``.

.. _Comments:

Comments
========

A comment begins with a ``#`` character and is ignored during processing.
Also each configuration section or sequence block allows a permanent
comment using the ``comment`` item which is stored in the server beside the
configuration.

.. _Includes:

Includes
========

Another configuration file or files, matching a pattern, can be included at
the top level in the current file. If the path is not absolute, then it
is considered to be relative to the current file. The pattern can be
an arbitrary string meeting POSIX *glob* requirements, e.g. dir/\*.conf.
Matching files are processed in sorted order.

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
     udp-workers: INT
     tcp-workers: INT
     background-workers: INT
     async-start: BOOL
     tcp-handshake-timeout: TIME
     tcp-idle-timeout: TIME
     tcp-reply-timeout: TIME
     max-tcp-clients: INT
     max-udp-payload: SIZE
     max-ipv4-udp-payload: SIZE
     max-ipv6-udp-payload: SIZE
     listen: ADDR[@INT] ...

.. _server_identity:

identity
--------

An identity of the server returned in the response to the query for TXT
record ``id.server.`` or ``hostname.bind.`` in the CHAOS class (see RFC 4892).
Set empty value to disable.

*Default:* FQDN hostname

.. _server_version:

version
-------

A version of the server software returned in the response to the query
for TXT record ``version.server.`` or ``version.bind.`` in the CHAOS
class (see RFC 4892). Set empty value to disable.

*Default:* server version

.. _server_nsid:

nsid
----

A DNS name server identifier (see RFC 5001). Set empty value to disable.

*Default:* FQDN hostname

.. _server_rundir:

rundir
------

A path for storing run-time data (PID file, unix sockets, etc.).

*Default:* ``${localstatedir}/run/knot`` (configured with ``--with-rundir=path``)

.. _server_user:

user
----

A system user with an optional system group (``user:group``) under which the
server is run after starting and binding to interfaces. Linux capabilities
are employed if supported.

*Default:* root:root

.. _server_pidfile:

pidfile
-------

A PID file location.

*Default:* :ref:`rundir<server_rundir>`/knot.pid

.. _server_udp-workers:

udp-workers
-----------

A number of UDP workers (threads) used to process incoming queries
over UDP.

*Default:* auto-estimated optimal value based on the number of online CPUs

.. _server_tcp-workers:

tcp-workers
-----------

A number of TCP workers (threads) used to process incoming queries
over TCP.

*Default:* auto-estimated optimal value based on the number of online CPUs

.. _server_background-workers:

background-workers
------------------

A number of workers (threads) used to execute background operations (zone
loading, zone updates, etc.).

*Default:* auto-estimated optimal value based on the number of online CPUs

.. _server_async-start:

async-start
-----------

If enabled, server doesn't wait for the zones to be loaded and starts
responding immediately with SERVFAIL answers until the zone loads.

*Default:* off

.. _server_tcp-handshake-timeout:

tcp-handshake-timeout
---------------------

Maximum time between newly accepted TCP connection and the first query.
This is useful to disconnect inactive connections faster than connections
that already made at least 1 meaningful query.

*Default:* 5

.. _server_tcp-idle-timeout:

tcp-idle-timeout
----------------

Maximum idle time between requests on a TCP connection. This also limits
receiving of a single query, each query must be received in this time limit.

*Default:* 20

.. _server_tcp-reply-timeout:

tcp-reply-timeout
-----------------

Maximum time to wait for an outgoing connection or for a reply to an issued
request (SOA, NOTIFY, AXFR...).

*Default:* 10

.. _server_max-tcp-clients:

max-tcp-clients
---------------

A maximum number of TCP clients connected in parallel, set this below the file
descriptor limit to avoid resource exhaustion.

*Default:* 100

.. _server_max-udp-payload:

max-udp-payload
---------------

Maximum EDNS0 UDP payload size default for both IPv4 and IPv6.

*Default:* 4096

.. _server_max-ipv4-udp-payload:

max-ipv4-udp-payload
--------------------

Maximum EDNS0 UDP payload size for IPv4.

*Default:* 4096

.. _server_max-ipv6-udp-payload:

max-ipv6-udp-payload
--------------------

Maximum EDNS0 UDP payload size for IPv6.

*Default:* 4096

.. _server_listen:

listen
------

One or more IP addresses where the server listens for incoming queries.
Optional port specification (default is 53) can be appended to each address
using ``@`` separator. Use ``0.0.0.0`` for all configured IPv4 addresses or
``::`` for all configured IPv6 addresses.

*Default:* not set

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

*Default:* not set

.. _key_secret:

secret
------

Shared key secret.

*Default:* not set

.. _ACL section:

ACL section
===========

Access control list rule definitions. The ACLs are used to match incoming
connections to allow or deny requested operation (zone transfer request, DDNS
update, etc.).

::

 acl:
   - id: STR
     address: ADDR[/INT] | ADDR-ADDR ...
     key: key_id ...
     action: notify | transfer | update ...
     deny: BOOL

.. _acl_id:

id
--

An ACL rule identifier.

.. _acl_address:

address
-------

An ordered list of IP addresses, network subnets, or network ranges. The query
must match one of them. Empty value means that address match is not required.

*Default:* not set

.. _acl_key:

key
---

An ordered list of :ref:`reference<key_id>`\ s to TSIG keys. The query must
match one of them. Empty value means that TSIG key is not required.

*Default:* not set

.. _acl_action:

action
------

An ordered list of allowed (or denied) actions.

Possible values:

- ``transfer`` – Allow zone transfer
- ``notify`` – Allow incoming notify
- ``update`` – Allow zone updates

*Default:* not set

.. _acl_deny:

deny
----

If enabled, instead of allowing, deny the specified :ref:`action<acl_action>`,
:ref:`address<acl_address>`, :ref:`key<acl_key>`, or combination if these
items. If no action is specified, deny all actions.

*Default:* off

.. _Control section:

Control section
===============

Configuration of the server control interface.

::

 control:
     listen: STR
     timeout: TIME

.. _control_listen:

listen
------

A UNIX socket path where the server listens for control commands.

*Default:* :ref:`rundir<server_rundir>`/knot.sock

.. _control_timeout:

timeout
-------

Maximum time the control socket operations can take. Set 0 for infinity.

*Default:* 5

.. _statistics_section:

Statistics section
==================

Periodic server statistics dumping.

::

  statistics:
      timer: TIME
      file: STR
      append: BOOL

.. _statistics_timer:

timer
-----

A period after which all available statistics metrics will by written to the
:ref:`file<statistics_file>`.

*Default:* not set

.. _statistics_file:

file
----

A file path of statistics output in the YAML format.

*Default:* :ref:`rundir<server_rundir>`/stats.yaml

.. _statistics_append:

append
------

If enabled, the output will be appended to the :ref:`file<statistics_file>`
instead of file replacement.

*Default:* off

.. _Keystore section:

Keystore section
================

DNSSEC keystore configuration.

::

 keystore:
   - id: STR
     backend: pem | pkcs11
     config: STR

.. _keystore_id:

id
--

A keystore identifier.


.. _keystore_backend:

backend
-------

A key storage backend type. A directory with PEM files or a PKCS #11 storage.

*Default:* pem

.. _keystore_config:

config
------

A backend specific configuration. A directory with PEM files (the path can
be specified as a relative path to :ref:`kasp-db<zone_kasp-db>`) or
a configuration string for PKCS #11 storage.

.. NOTE::
   Example configuration string for PKCS #11::

     "pkcs11:token=knot;pin-value=1234 /usr/lib64/pkcs11/libsofthsm2.so"

*Default:* :ref:`kasp-db<zone_kasp-db>`/keys

.. _Policy section:

Policy section
==============

DNSSEC policy configuration.

::

 policy:
   - id: STR
     keystore: STR
     manual: BOOL
     single-type-signing: BOOL
     algorithm: dsa | rsasha1 | dsa-nsec3-sha1 | rsasha1-nsec3-sha1 | rsasha256 | rsasha512 | ecdsap256sha256 | ecdsap384sha384
     ksk-size: SIZE
     zsk-size: SIZE
     dnskey-ttl: TIME
     zsk-lifetime: TIME
     propagation-delay: TIME
     rrsig-lifetime: TIME
     rrsig-refresh: TIME
     nsec3: BOOL
     nsec3-iterations: INT
     nsec3-salt-length: INT
     nsec3-salt-lifetime: TIME

.. _policy_id:

id
--

A policy identifier.

.. _policy_keystore:

keystore
--------

A :ref:`reference<keystore_id>` to a keystore holding private key material
for zones. A special *default* value can be used for the default keystore settings.

*Default:* default

.. _policy_manual:

manual
------

If enabled, automatic key management is not used.

*Default:* off

.. _policy_single-type-signing:

single-type-signing
-------------------

If enabled, Single-Type Signing Scheme is used in the automatic key management
mode.

.. NOTE::
   Because key rollover is not supported yet, just one combined signing key is
   generated if none is available.

*Default:* off

.. _policy_algorithm:

algorithm
---------

An algorithm of signing keys and issued signatures.

*Default:* ecdsap256sha256

.. _policy_ksk-size:

ksk-size
--------

A length of newly generated :abbr:`KSK (Key Signing Key)` keys.

*Default:* 1024 (dsa*), 2048 (rsa*), 256 (ecdsap256*), 384 (ecdsap384*)

.. _policy_zsk-size:

zsk-size
--------

A length of newly generated :abbr:`ZSK (Zone Signing Key)` keys.

*Default:* see default for :ref:`ksk-size<policy_ksk-size>`

.. _policy_dnskey-ttl:

dnskey-ttl
----------

A TTL value for DNSKEY records added into zone apex.

*Default:* zone SOA TTL

.. NOTE::
   has infuence over ZSK key lifetime

.. _policy_zsk-lifetime:

zsk-lifetime
------------

A period between ZSK publication and the next rollover initiation.

*Default:* 30 days

.. NOTE::
   ZSK key lifetime is also infuenced by propagation-delay and dnskey-ttl

.. _policy_propagation-delay:

propagation-delay
-----------------

An extra delay added for each key rollover step. This value should be high
enough to cover propagation of data from the master server to all slaves.

*Default:* 1 day

.. NOTE::
   has infuence over ZSK key lifetime

.. _policy_rrsig-lifetime:

rrsig-lifetime
--------------

A validity period of newly issued signatures.

*Default:* 14 days

.. _policy_rrsig-refresh:

rrsig-refresh
-------------

A period how long before a signature expiration the signature will be refreshed.

*Default:* 7 days

.. _policy_nsec:

nsec3
-----

Specifies if NSEC3 will be used instead of NSEC.

*Default:* off

.. _policy_nsec3-iterations:

nsec3-iterations
----------------

A number of additional times the hashing is performed.

*Default:* 5

.. _policy_nsec3-salt-length:

nsec3-salt-length
-----------------

A length of a salt field in octets, which is appended to the original owner
name before hashing.

*Default:* 8

.. _policy_nsec3-salt-lifetime:

nsec3-salt-lifetime
-------------------

A validity period of newly issued salt field.

*Default:* 30 days

.. _Remote section:

Remote section
==============

Definitions of remote servers for outgoing connections (source of a zone
transfer, target for a notification, etc.).

::

 remote:
   - id: STR
     address: ADDR[@INT] ...
     via: ADDR[@INT] ...
     key: key_id

.. _remote_id:

id
--

A remote identifier.

.. _remote_address:

address
-------

An ordered list of destination IP addresses which are used for communication
with the remote server. The addresses are tried in sequence unless the
operation is successful. Optional destination port (default is 53)
can be appended to the address using ``@`` separator.

*Default:* not set

.. _remote_via:

via
---

An ordered list of source IP addresses. The first address with the same family
as the destination address is used. Optional source port (default is random)
can be appended to the address using ``@`` separator.

*Default:* not set

.. _remote_key:

key
---

A :ref:`reference<key_id>` to the TSIG key which is used to authenticate
the communication with the remote server.

*Default:* not set

.. _Template section:

Template section
================

A template is a shareable zone setting which can be used for configuration of
many zones in one place. A special default template (with the *default* identifier)
can be used for global querying configuration or as an implicit configuration
if a zone doesn't have another template specified.

::

 template:
   - id: STR
     timer-db: STR
     journal-db: STR
     journal-db-mode: robust | asynchronous
     max-journal-db-size: SIZE
     global-module: STR/STR ...
     # All zone options (excluding 'template' item)

.. _template_id:

id
--

A template identifier.

.. _template_timer-db:

timer-db
--------

Specifies a path of the persistent timer database. The path can be specified
as a relative path to the *default* template :ref:`storage<zone_storage>`.

.. NOTE::
   This option is only available in the *default* template.

*Default:* :ref:`storage<zone_storage>`/timers

.. _template_journal-db:

journal-db
----------

Specifies a path of the persistent journal database. The path can be specified
as a relative path to the *default* template :ref:`storage<zone_storage>`.

.. NOTE::
   This option is only available in the *default* template.

*Default:* :ref:`storage<zone_storage>`/journal

.. _template_journal-db-mode:

journal-db-mode
---------------

Specifies journal LMDB backend configuration, which influences performance
and durability.

Possible values:

- ``robust`` – The journal DB disk sychronization ensures DB durability but is
  generally slower
- ``asynchronous`` – The journal DB disk synchronization is optimized for
  better perfomance at the expense of lower DB durability; this mode is
  recommended only on slave nodes with many zones

.. NOTE::
   This option is only available in the *default* template.

*Default:* robust

.. _template_max-journal-db-size:

max-journal-db-size
-------------------

Hard limit for the common journal DB. There is no cleanup logic in journal
to recover from reaching this limit: journal simply starts refusing changes
across all zones. Decreasing this value has no effect if lower than actual
DB file size.

It is recommended to limit :ref:`max-journal-usage<zone_max-journal-usage>`
per-zone instead of max-journal-size in most cases. Please keep this value
large enough. This value also influences server's usage of virtual memory.

.. NOTE::
   This option is only available in the *default* template.

*Default:* 20 GiB

.. _template_global-module:

global-module
-------------

An ordered list of references to query modules in the form of *module_name* or
*module_name/module_id*. These modules apply to all queries.

.. NOTE::
   This option is only available in the *default* template.

*Default:* not set

.. _Zone section:

Zone section
============

Definition of zones served by the server.

::

 zone:
   - domain: DNAME
     template: template_id
     storage: STR
     file: STR
     master: remote_id ...
     ddns-master: remote_id
     notify: remote_id ...
     acl: acl_id ...
     semantic-checks: BOOL
     disable-any: BOOL
     zonefile-sync: TIME
     ixfr-from-differences: BOOL
     max-journal-usage: SIZE
     max-journal-depth: INT
     max-zone-size : SIZE
     dnssec-signing: BOOL
     dnssec-policy: STR
     kasp-db: STR
     request-edns-option: INT:[HEXSTR]
     serial-policy: increment | unixtime
     module: STR/STR ...

.. _zone_domain:

domain
------

A zone name identifier.

.. _zone_template:

template
--------

A :ref:`reference<template_id>` to a configuration template.

*Default:* not set or *default* (if the template exists)

.. _zone_storage:

storage
-------

A data directory for storing zone files, journal files and timers database.

*Default:* ``${localstatedir}/lib/knot`` (configured with ``--with-storage=path``)

.. _zone_file:

file
----

A path to the zone file. Non absolute path is relative to
:ref:`storage<zone_storage>`. It is also possible to use the following formatters:

- ``%c[``\ *N*\ ``]`` or ``%c[``\ *N*\ ``-``\ *M*\ ``]`` – means the *N*\ th
  character or a sequence of characters beginning from the *N*\ th and ending
  with the *M*\ th character of the textual zone name (see ``%s``). The
  indexes are counted from 0 from the left. All dots (including the terminal
  one) are considered. If the character is not available, the formatter has no effect.
- ``%l[``\ *N*\ ``]`` – means the *N*\ th label of the textual zone name
  (see ``%s``). The index is counted from 0 from the right (0 ~ TLD).
  If the label is not available, the formatter has no effect.
- ``%s`` – means the current zone name in the textual representation (beware
  of special characters which are escaped or encoded in the \\DDD form where
  DDD is corresponding decimal ASCII code). The zone name doesn't include the
  terminating dot (the result for the root zone is the empty string!).
- ``%%`` – means the ``%`` character

*Default:* :ref:`storage<zone_storage>`/``%s``\ .zone

.. _zone_master:

master
------

An ordered list of :ref:`references<remote_id>` to zone master servers.

*Default:* not set

.. _zone_ddns-master:

ddns-master
-----------

A :ref:`reference<remote_id>` to zone primary master server.
If not specified, the first :ref:`master<zone_master>` server is used.

*Default:* not set

.. _zone_notify:

notify
------

An ordered list of :ref:`references<remote_id>` to remotes to which notify
message is sent if the zone changes.

*Default:* not set

.. _zone_acl:

acl
---

An ordered list of :ref:`references<acl_id>` to ACL rules which can allow
or disallow zone transfers, updates or incoming notifies.

*Default:* not set

.. _zone_semantic-checks:

semantic-checks
---------------

If enabled, extra zone file semantic checks are turned on.

Several checks are enabled by default and cannot be turned off. An error in
mandatory checks causes zone not to be loaded. An error in extra checks is
logged only.

Mandatory checks:

- An extra record together with CNAME record (except for RRSIG and DS)
- SOA record missing in the zone (RFC 1034)
- DNAME records having records under it (DNAME children) (RFC 2672)

Extra checks:

- Missing NS record at the zone apex
- Missing glue A or AAAA records
- Broken or non-cyclic NSEC(3) chain
- Wrong NSEC(3) type bitmap
- Multiple NSEC records at the same node
- Missing NSEC records at authoritative nodes
- NSEC3 insecure delegation that is not part of Opt-out span
- Wrong original TTL value in NSEC3 records
- Wrong RDATA TTL value in RRSIG record
- Signer name in RRSIG RR not the same as in DNSKEY
- Signed RRSIG
- Wrong key flags or wrong key in RRSIG record (not the same as ZSK)

*Default:* off

.. _zone_disable-any:

disable-any
-----------

If enabled, all authoritative ANY queries sent over UDP will be answered
with an empty response and with the TC bit set. Use this option to minimize
the risk of DNS reflection attack.

*Default:* off

.. _zone_zonefile-sync:

zonefile-sync
-------------

The time after which the current zone in memory will be synced with a zone file
on the disk (see :ref:`file<zone_file>`). The server will serve the latest
zone even after a restart using zone journal, but the zone file on the disk will
only be synced after ``zonefile-sync`` time has expired (or after manual zone
flush). This is applicable when the zone is updated via IXFR, DDNS or automatic
DNSSEC signing. In order to disable automatic zonefile synchronization, -1 value
can be used (manual zone flush is still possible).

.. NOTE::
   If you are serving large zones with frequent updates where
   the immediate sync with a zone file is not desirable, increase the value.

.. WARNING::
   If the zone file is not up-to-date, the zone should be flushed before its
   zone file editation or the SOA record must be untouched after editation.
   Otherwise the journal can't be applied.

*Default:* 0 (immediate)

.. _zone_ixfr-from-differences:

ixfr-from-differences
---------------------

If enabled, the server creates zone differences from changes you made to the
zone file upon server reload. This option is relevant only if the server
is a master server for the zone.

.. NOTE::
   This option has no effect with enabled
   :ref:`dnssec-signing<zone_dnssec-signing>`.

*Default:* off

.. _zone_max-journal-usage:

max-journal-usage
-----------------

Policy how much space in journal DB will the zone's journal occupy.

*Default:* 100 MiB

.. NOTE::
   Journal DB may grow far above the sum of max-journal-usage across
   all zones, because of DB free space fragmentation.

.. _zone_max_journal_depth:

max-journal-depth
-----------------

Maximum history length of journal.

*Default:* 2^64

.. _zone_max_zone_size:

max-zone-size
----------------

Maximum size of the zone. The size is measured as size of the zone records
in wire format without compression. The limit is enforced for incoming zone
transfers and dynamic updates.

For incremental transfers (IXFR), the effective limit for the total size of
the records in the transfer is twice the configured value. However the final
size of the zone must satisfy the configured value.

*Default:* 2^64

.. _zone_dnssec-signing:

dnssec-signing
--------------

If enabled, automatic DNSSEC signing for the zone is turned on.

.. NOTE::
   Cannot be enabled on a slave zone.

*Default:* off

.. _zone_dnssec-policy:

dnssec-policy
-------------

A :ref:`reference<policy_id>` to DNSSEC signing policy. A special *default*
value can be used for the default policy settings.

*Required*

.. _zone_kasp-db:

kasp-db
-------

A KASP database path. Non absolute path is relative to
:ref:`storage<zone_storage>`.

*Default:* :ref:`storage<zone_storage>`/keys

.. _zone_request_edns_option:

request-edns-option
-------------------

An arbitrary EDNS0 option which is included into a server request (AXFR, IXFR,
SOA, or NOTIFY). The value is in the option_code:option_data format.

*Default:* not set

.. _zone_serial-policy:

serial-policy
-------------

Specifies how the zone serial is updated after a dynamic update or
automatic DNSSEC signing. If the serial is changed by the dynamic update,
no change is made.

Possible values:

- ``increment`` – The serial is incremented according to serial number arithmetic
- ``unixtime`` – The serial is set to the current unix time

.. NOTE::
   If your serial was in other than unix time format, be careful
   with the transition to unix time.  It may happen that the new serial will
   be \'lower\' than the old one. If this is the case, the transition should be
   done by hand (see RFC 1982).

*Default:* increment

.. _zone_module:

module
------

An ordered list of references to query modules in the form of *module_name* or
*module_name/module_id*. These modules apply only to the current zone queries.

*Default:* not set

.. _Logging section:

Logging section
===============

Server can be configured to log to the standard output, standard error
output, syslog (or systemd journal if systemd is enabled) or into an arbitrary
file.

There are 6 logging severity levels:

- ``critical`` – Non-recoverable error resulting in server shutdown

- ``error`` – Recoverable error, action should be taken

- ``warning`` – Warning that might require user action

- ``notice`` – Server notice or hint

- ``info`` – Informational message

- ``debug`` – Debug messages (must be turned on at compile time)

In the case of missing log section, ``warning`` or more serious messages
will be logged to both standard error output and syslog. The ``info`` and
``notice`` messages will be logged to standard output.

::

 log:
   - target: stdout | stderr | syslog | STR
     server: critical | error | warning | notice | info | debug
     control: critical | error | warning | notice | info | debug
     zone: critical | error | warning | notice | info | debug
     any: critical | error | warning | notice | info | debug

.. _log_target:

target
------

A logging output.

Possible values:

- ``stdout`` – Standard output
- ``stderr`` – Standard error output
- ``syslog`` – Syslog
- *file\_name* – File

.. _log_server:

server
------

Minimum severity level for messages related to general operation of the server
that are logged.

*Default:* not set

.. _log_control:

control
-------

Minimum severity level for messages related to server control that are logged.

*Default:* not set

.. _log_zone:

zone
----

Minimum severity level for messages related to zones that are logged.

*Default:* not set

.. _log_any:

any
---

Minimum severity level for all message types that are logged.

*Default:* not set

.. _mod-rrl:

Module rrl
==========

A response rate limiting module.

::

 mod-rrl:
   - id: STR
     rate-limit: INT
     slip: INT
     table-size: INT
     whitelist: ADDR[/INT] | ADDR-ADDR ...

.. _mod-rrl_id:

id
--

A module identifier.

.. _mod-rrl_rate-limit:

rate-limit
----------

Rate limiting is based on the token bucket scheme. A rate basically
represents a number of tokens available each second. Each response is
processed and classified (based on several discriminators, e.g.
source netblock, query type, zone name, rcode, etc.). Classified responses are
then hashed and assigned to a bucket containing number of available
tokens, timestamp and metadata. When available tokens are exhausted,
response is dropped or sent as truncated (see :ref:`mod-rrl_slip`).
Number of available tokens is recalculated each second.

*Required*

.. _mod-rrl_table-size:

table-size
----------

Size of the hash table in a number of buckets. The larger the hash table, the lesser
the probability of a hash collision, but at the expense of additional memory costs.
Each bucket is estimated roughly to 32 bytes. The size should be selected as
a reasonably large prime due to better hash function distribution properties.
Hash table is internally chained and works well up to a fill rate of 90 %, general
rule of thumb is to select a prime near 1.2 * maximum_qps.

*Default:* 393241

.. _mod-rrl_slip:

slip
----

As attacks using DNS/UDP are usually based on a forged source address,
an attacker could deny services to the victim's netblock if all
responses would be completely blocked. The idea behind SLIP mechanism
is to send each N\ :sup:`th` response as truncated, thus allowing client to
reconnect via TCP for at least some degree of service. It is worth
noting, that some responses can't be truncated (e.g. SERVFAIL).

- Setting the value to **0** will cause that all rate-limited responses will
  be dropped. The outbound bandwidth and packet rate will be strictly capped
  by the :ref:`mod-rrl_rate-limit` option. All legitimate requestors affected
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

*Default:* 1

.. _mod-rrl_whitelist:

whitelist
---------

A list of IP addresses, network subnets, or network ranges to exempt from
rate limiting. Empty list means that no incoming connection will be
white-listed.

*Default:* not set

.. _Module dnstap:

Module dnstap
=============

The module dnstap allows query and response logging.

For all queries logging, use this module in the *default* template. For
zone-specific logging, use this module in the proper zone configuration.

::

 mod-dnstap:
   - id: STR
     sink: STR
     identity: STR
     version: STR
     log-queries: BOOL
     log-responses: BOOL

.. _mod-dnstap_id:

id
--

A module identifier.

.. _mod-dnstap_sink:

sink
----

A sink path, which can be either a file or a UNIX socket when prefixed with
``unix:``.

*Required*

.. _mod-dnstap_identity:

identity
--------

A DNS server identity. Set empty value to disable.

*Default:* FQDN hostname

.. _mod-dnstap_version:

version
-------

A DNS server version. Set empty value to disable.

*Default:* server version

.. _mod-dnstap_log-queries:

log-queries
-----------

If enabled, query messages will be logged.

*Default:* on

.. _mod-dnstap_log-responses:

log-responses
-------------

If enabled, response messages will be logged.

*Default:* on

.. _Module online-sign:

Module online-sign
==================

The module provides online DNSSEC signing. Instead of pre-computing the zone signatures
when the zone is loaded into the server or instead of loading an externally signed zone,
the signatures are computed on-the-fly during answering.

::

 mod-online-sign:
   - id: STR
     policy: STR

.. _mod-online-sign_id:

id
--

A module identifier.

.. _mod-online-sign_policy:

policy
------

A :ref:`reference<policy_id>` to DNSSEC signing policy. A special *default*
value can be used for the default policy settings.

.. _Module synth-record:

Module synth-record
===================

This module is able to synthesize either forward or reverse records for the
given prefix and subnet.

::

 mod-synth-record:
   - id: STR
     type: forward | reverse
     prefix: STR
     origin: DNAME
     ttl: INT
     network: ADDR[/INT] | ADDR-ADDR

.. _mod-synth-record_id:

id
--

A module identifier.

.. _mod-synth-record_type:

type
----

The type of generated records.

Possible values:

- ``forward`` – Forward records
- ``reverse`` – Reverse records

*Required*

.. _mod-synth-record_prefix:

prefix
------

A record owner prefix.

.. NOTE::
   The value doesn’t allow dots, address parts in the synthetic names are
   separated with a dash.

*Default:* empty

.. _mod-synth-record_origin:

origin
------

A zone origin (only valid for the :ref:`reverse type<mod-synth-record_type>`).

*Required*

.. _mod-synth-record_ttl:

ttl
---

Time to live of the generated records.

*Default:* 3600

.. _mod-synth-record_network:

network
-------

An IP address, a network subnet, or a network range the query must match.

*Required*

.. _Module dnsproxy:

Module dnsproxy
===============

The module catches all unsatisfied queries and forwards them to the indicated
server for resolution.

::

 mod-dnsproxy:
   - id: STR
     remote: remote_id
     timeout: INT
     fallback: BOOL
     catch-nxdomain: BOOL

.. _mod-dnsproxy_id:

id
--

A module identifier.

.. _mod-dnsproxy_remote:

remote
------

A :ref:`reference<remote_id>` to a remote server where the queries are
forwarded to.

*Required*

.. _mod-dnsproxy_timeout:

timeout
-------

A remote response timeout in milliseconds.

*Default:* 500

.. _mod-dnsproxy_fallback:

fallback
--------

If enabled, localy unsatisfied queries leading to REFUSED (no zone) are forwarded.
If disabled, all queries are directly forwarded without any local attempts
to resolve them.

*Default:* on

.. _mod-dnsproxy_catch-nxdomain:

catch-nxdomain
--------------

If enabled, localy unsatisfied queries leading to NXDOMAIN are forwarded.
This option is only relevant in the fallback mode.

*Default:* off

.. _Module rosedb:

Module rosedb
=============

The module provides a mean to override responses for certain queries before
the available zones are searched for the record.

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

A path to the directory where the database is stored.

*Required*

.. _mod-stats:

Module stats
============

The module provides incoming query processing statistics.

.. NOTE::
   Leading 16-bit message size over TCP is not considered.

::

 mod-stats:
   - id: STR
     request-protocol: BOOL
     server-operation: BOOL
     request-bytes: BOOL
     response-bytes: BOOL
     edns-presence: BOOL
     flag-presence: BOOL
     response-code: BOOL
     reply-nodata: BOOL
     query-type: BOOL
     query-size: BOOL
     reply-size: BOOL

.. _mod-stats_id:

id
--

A module identifier.

.. _mod-stats_request-protocol:

request-protocol
----------------

If enabled, all incoming requests are counted by the network protocol:

* udp4 - UDP over IPv4
* tcp4 - TCP over IPv4
* udp6 - UDP over IPv6
* tcp6 - TCP over IPv6

*Default:* on

.. _mod-stats_server-operation:

server-operation
----------------

If enabled, all incoming requests are counted by the server operation. The
server operation is based on message header OpCode and message query (meta) type:

* query - Normal query operation
* update - Dynamic update operation
* notify - NOTIFY request operation
* axfr - Full zone transfer operation
* ixfr - Incremental zone transfer operation
* invalid - Invalid server operation

*Default:* on

.. _mod-stats_request-bytes:

request-bytes
-------------

If enabled, all incoming request bytes are counted by the server operation:

* query - Normal query bytes
* update - Dynamic update bytes
* other - Other request bytes

*Default:* on

.. _mod-stats_response-bytes:

response-bytes
--------------

If enabled, outgoing response bytes are counted by the server operation:

* reply - Normal response bytes
* transfer - Zone transfer bytes
* other - Other response bytes

.. WARNING::
   Dynamic update response bytes are not counted by this module.

*Default:* on

.. _mod-stats_edns-presence:

edns-presence
-------------

If enabled, EDNS pseudo section presence is counted by the message direction:

* request - EDNS present in request
* response - EDNS present in response

*Default:* off

.. _mod-stats_flag-presence:

flag-presence
-------------

If enabled, some message header flags are counted:

* TC - Truncated Answer in response
* DO - DNSSEC OK in request

*Default:* off

.. _mod-stats_response-code:

response-code
-------------

If enabled, outgoing response code is counted:

* NOERROR
* ...
* NOTZONE
* BADVERS
* ...
* BADCOOKIE
* other - All other codes

.. NOTE::
   In the case of multi-message zone transfer response, just one counter is
   incremented.

.. WARNING::
   Dynamic update response code is not counted by this module.

*Default:* on

.. _mod-stats_reply-nodata:

reply-nodata
------------

If enabled, NODATA pseudo RCODE (see RFC 2308, Section 2.2) is counted by the
query type:

* A
* AAAA
* other - All other types

*Default:* off

.. _mod-stats_query-type:

query-type
----------

If enabled, normal query type is counted:

* A (TYPE1)
* ...
* TYPE65
* SPF (TYPE99)
* ...
* TYPE110
* ANY (TYPE255)
* ...
* TYPE260
* other - All other types

.. NOTE::
   Not all assigned meta types (IXFR, AXFR,...) have their own counters,
   because such types are not processed as normal query.

*Default:* off

.. _mod-stats_query-size:

query-size
----------

If enabled, normal query message size distribution is counted by the size range
in bytes:

* 0-15
* 16-31
* ...
* 272-287
* 288-65535

*Default:* off

.. _mod-stats_reply-size:

reply-size
----------

If enabled, normal reply message size distribution is counted by the size range
in bytes:

* 0-15
* 16-31
* ...
* 4080-4095
* 4096-65535

*Default:* off
