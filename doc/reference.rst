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

The configuration consists of several fixed sections and optional module
sections. There are 15 fixed sections (``module``, ``server``, ``xdp``, ``control``,
``log``, ``statistics``, ``database``, ``keystore``, ``key``, ``remote``,
``acl``, ``submission``, ``policy``, ``template``, ``zone``).
Module sections are prefixed with the ``mod-`` prefix (e.g. ``mod-stats``).

Most of the sections (e.g. ``zone``) are sequences of settings blocks. Each
settings block begins with a unique identifier, which can be used as a reference
from other sections (such an identifier must be defined in advance).

A multi-valued item can be specified either as a YAML sequence::

 address: [10.0.0.1, 10.0.0.2]

or as more single-valued items each on an extra line::

 address: 10.0.0.1
 address: 10.0.0.2

If an item value contains spaces or other special characters, it is necessary
to enclose such a value within double quotes ``"`` ``"``.

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

.. _Module section:

Module section
==============

Dynamic modules loading configuration.

.. NOTE::
   If configured with non-empty ```--with-moduledir=path``` parameter, all
   shared modules in this directory will be automatically loaded.

::

 module:
   - id: STR
     file: STR

.. _module_id:

id
--

A module identifier in the form of the ``mod-`` prefix and module name suffix.

.. _module_file:

file
----

A path to a shared library file with the module implementation.

.. WARNING::
   If the path is not absolute, the library is searched in the set of
   system directories. See ``man dlopen`` for more details.

*Default:* ``${libdir}/knot/modules-${version}``/module_name.so
(or ``${path}``/module_name.so if configured with ``--with-moduledir=path``)

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
     tcp-idle-timeout: TIME
     tcp-io-timeout: INT
     tcp-remote-io-timeout: INT
     tcp-max-clients: INT
     tcp-reuseport: BOOL
     tcp-fastopen: BOOL
     socket-affinity: BOOL
     udp-max-payload: SIZE
     udp-max-payload-ipv4: SIZE
     udp-max-payload-ipv6: SIZE
     edns-client-subnet: BOOL
     answer-rotation: BOOL
     listen: ADDR[@INT] ...

.. CAUTION::
   When you change configuration parameters dynamically or via configuration file
   reload, some parameters in the Server section require restarting the Knot server
   so that the changes take effect. See below for the details.

.. _server_identity:

identity
--------

An identity of the server returned in the response to the query for TXT
record ``id.server.`` or ``hostname.bind.`` in the CHAOS class (:rfc:`4892`).
Set to an empty value to disable.

*Default:* FQDN hostname

.. _server_version:

version
-------

A version of the server software returned in the response to the query
for TXT record ``version.server.`` or ``version.bind.`` in the CHAOS
class (:rfc:`4892`). Set to an empty value to disable.

*Default:* server version

.. _server_nsid:

nsid
----

A DNS name server identifier (:rfc:`5001`). Set to an empty value to disable.

*Default:* FQDN hostname at the moment of the daemon start

.. _server_rundir:

rundir
------

A path for storing run-time data (PID file, unix sockets, etc.).

Depending on the usage of this parameter, its change may require restart of the Knot
server to take effect.

*Default:* ``${localstatedir}/run/knot`` (configured with ``--with-rundir=path``)

.. _server_user:

user
----

A system user with an optional system group (``user:group``) under which the
server is run after starting and binding to interfaces. Linux capabilities
are employed if supported.

Change of this parameter requires restart of the Knot server to take effect.

*Default:* root:root

.. _server_pidfile:

pidfile
-------

A PID file location.

Change of this parameter requires restart of the Knot server to take effect.

*Default:* :ref:`rundir<server_rundir>`/knot.pid

.. _server_udp-workers:

udp-workers
-----------

A number of UDP workers (threads) used to process incoming queries
over UDP.

Change of this parameter requires restart of the Knot server to take effect.

*Default:* equal to the number of online CPUs

.. _server_tcp-workers:

tcp-workers
-----------

A number of TCP workers (threads) used to process incoming queries
over TCP.

Change of this parameter requires restart of the Knot server to take effect.

*Default:* equal to the number of online CPUs, default value is at least 10

.. _server_background-workers:

background-workers
------------------

A number of workers (threads) used to execute background operations (zone
loading, zone updates, etc.).

Change of this parameter requires restart of the Knot server to take effect.

*Default:* equal to the number of online CPUs, default value is at most 10

.. _server_async-start:

async-start
-----------

If enabled, server doesn't wait for the zones to be loaded and starts
responding immediately with SERVFAIL answers until the zone loads.

*Default:* off

.. _server_tcp-idle-timeout:

tcp-idle-timeout
----------------

Maximum idle time (in seconds) between requests on an inbound TCP connection.
It means if there is no activity on an inbound TCP connection during this limit,
the connection is closed by the server.

*Minimum:* 1 s

*Default:* 10 s

.. _server_tcp-io-timeout:

tcp-io-timeout
--------------

Maximum time (in milliseconds) to receive or send one DNS message over an inbound
TCP connection. It means this limit applies to normal DNS queries and replies,
incoming DDNS, and **outgoing zone transfers**. The timeout is measured since some
data is already available for processing.
Set to 0 for infinity.

*Default:* 500 ms

.. CAUTION::
   In order to reduce the risk of Slow Loris attacks, it's recommended setting
   this limit as low as possible on public servers.

.. _server_tcp-remote-io-timeout:

tcp-remote-io-timeout
---------------------

Maximum time (in milliseconds) to receive or send one DNS message over an outbound
TCP connection which has already been established to a configured remote server.
It means this limit applies to incoming zone transfers, sending NOTIFY,
DDNS forwarding, and DS check or push. This timeout includes the time needed
for a network round-trip and for a query processing by the remote.
Set to 0 for infinity.

*Default:* 5000 ms

.. _server_tcp-reuseport:

tcp-reuseport
-------------

If enabled, each TCP worker listens on its own socket and the OS kernel
socket load balancing is employed using SO_REUSEPORT (or SO_REUSEPORT_LB
on FreeBSD). Due to the lack of one shared socket, the server can offer
higher response rate processing over TCP. However, in the case of
time-consuming requests (e.g. zone transfers of a TLD zone), enabled reuseport
may result in delayed or not being responded client requests. So it is
advisable to use this option on secondary servers.

Change of this parameter requires restart of the Knot server to take effect.

*Default:* off

.. _server_tcp-fastopen:

tcp-fastopen
------------

If enabled, use TCP Fast Open for outbound TCP communication (client side):
incoming zone transfers, sending NOTIFY, and DDNS forwarding. This mode simplifies
TCP handshake and can result in better networking performance. TCP Fast Open
for inbound TCP communication (server side) isn't affected by this
configuration as it's enabled automatically if supported by OS.

.. NOTE::
   The TCP Fast Open support must also be enabled on the OS level:

   * Linux/macOS: ensure kernel parameter ``net.ipv4.tcp_fastopen`` is ``2`` or
     ``3`` for server side, and ``1`` or ``3`` for client side.
   * FreeBSD: ensure kernel parameter ``net.inet.tcp.fastopen.server_enable``
     is ``1`` for server side, and ``net.inet.tcp.fastopen.client_enable`` is
     ``1`` for client side.

*Default:* off

.. _server_socket-affinity:

socket-affinity
---------------

If enabled and if SO_REUSEPORT is available on Linux, all configured network
sockets are bound to UDP and TCP workers in order to increase the networking performance.
This mode isn't recommended for setups where the number of network card queues
is lower than the number of UDP or TCP workers.

Change of this parameter requires restart of the Knot server to take effect.

*Default:* off

.. _server_tcp-max-clients:

tcp-max-clients
---------------

A maximum number of TCP clients connected in parallel, set this below the file
descriptor limit to avoid resource exhaustion.

.. NOTE::
   It is advisable to adjust the maximum number of open files per process in your
   operating system configuration.

*Default:* one half of the file descriptor limit for the server process

.. _server_udp-max-payload:

udp-max-payload
---------------

Maximum EDNS0 UDP payload size default for both IPv4 and IPv6.

*Default:* 1232

.. _server_udp-max-payload-ipv4:

udp-max-payload-ipv4
--------------------

Maximum EDNS0 UDP payload size for IPv4.

*Default:* 1232

.. _server_udp-max-payload-ipv6:

udp-max-payload-ipv6
--------------------

Maximum EDNS0 UDP payload size for IPv6.

*Default:* 1232

.. _server_edns-client-subnet:

edns-client-subnet
------------------

Enable or disable EDNS Client Subnet support. If enabled, responses to queries
containing the EDNS Client Subnet option
always contain a valid EDNS Client Subnet option according to :rfc:`7871`.

*Default:* off

.. _server_answer-rotation:

answer-rotation
---------------

Enable or disable sorted-rrset rotation in the answer section of normal replies.
The rotation shift is simply determined by a query ID.

*Default:* off

.. _server_listen:

listen
------

One or more IP addresses where the server listens for incoming queries.
Optional port specification (default is 53) can be appended to each address
using ``@`` separator. Use ``0.0.0.0`` for all configured IPv4 addresses or
``::`` for all configured IPv6 addresses. Filesystem path can be specified
for listening on local unix SOCK_STREAM socket. Non-local address binding
is automatically enabled if supported by the operating system.

Change of this parameter requires restart of the Knot server to take effect.

*Default:* not set

.. _XDP section:

XDP section
===========

Various options related to XDP listening, especially TCP.

::

 xdp:
     listen: STR[@INT] | ADDR[@INT] ...
     tcp: BOOL
     tcp-max-clients: INT
     tcp-inbuf-max-size: SIZE
     tcp-idle-close-timeout: TIME
     tcp-idle-reset-timeout: TIME
     route-check: BOOL

.. CAUTION::
   When you change configuration parameters dynamically or via configuration file
   reload, some parameters in the XDP section require restarting the Knot server
   so that the changes take effect.

.. _xdp_listen:

listen
------

One or more network device names (e.g. ``ens786f0``) on which the :ref:`Mode XDP`
is enabled. Alternatively, an IP address can be used instead of a device name,
but the server will still listen on all addresses belonging to the same interface!
Optional port specification (default is 53) can be appended to each device name
or address using ``@`` separator.

Change of this parameter requires restart of the Knot server to take effect.

.. CAUTION::
   If XDP workers only process regular DNS traffic over UDP, it is strongly
   recommended to also :ref:`listen <server_listen>` on the addresses which are
   intended to offer the DNS service, at least to fulfil the DNS requirement for
   working TCP.

*Default:* not set

.. _xdp_tcp:

tcp
---

If enabled, DNS over TCP traffic is also processed with XDP workers.

The TCP stack features:

- Basic connection handling, sending/receiving data
- Close inactive connections
- Reset inactive connections which aren't able to close
- Reset invalid connections
- Ignore invalid resets and ACKs
- Receive fragmented data – one DNS message in multiple packets
- Limit total size of incoming buffers, reset most inactive connections
  with buffered data
- Send fragmented data – DNS message larger than allowed by MSS
- Send MSS option calculated from configured MSS and device MTU
- Receive and honor MSS option, limit the size of outgoing packet
- Send window size option (set to infinity)

Missing features:

- Receive and honor window size option, send only such amount of data at once,
  cache outgoing data
- Allow multi-message DNS responses (depends on above)
- Resend lost outgoing packets (not ACKed in time), including data

Change of this parameter requires restart of the Knot server to take effect.

.. WARNING::
   This feature is experimental and it may eat your hamster as well as any
   other hamsters connected to the network.

*Default:* off

.. _xdp_tcp-max-clients:

tcp-max-clients
---------------

A maximum number of TCP clients connected in parallel.

*Default:* 1000000 (one million)

.. _xdp_tcp-inbuf-max-size:

tcp-inbuf-max-size
------------------

Maximum cumulative size of memory used for buffers of incompletely
received messages.

*Minimum:* 1 MiB

*Default:* 100 MiB

.. _xdp_tcp-idle-close-timeout:

tcp-idle-close-timeout
----------------------

Time in seconds, after which any idle connection is gracefully closed.

*Minimum:* 1 s

*Default:* 10 s

.. _xdp_tcp-idle-reset-timeout:

tcp-idle-reset-timeout
----------------------

Time in seconds, after which any idle connection is forcibly closed.

*Minimum:* 1 s

*Default:* 20 s

.. _xdp_route-check:

route-check
-----------

If enabled, routing information from the operating system is considered
when processing every incoming DNS packet received over the XDP interface:

- If the outgoing interface of the corresponding DNS response differs from
  the incoming one, the packet is processed normally by UDP/TCP workers
  (XDP isn't used).
- If the destination address is blackholed, unreachable, or prohibited,
  the DNS packet is dropped without any response.
- The destination MAC address for the response is taken from the routing system.

If disabled, symmetrical routing is applied. It means that the query source
MAC address is used as a response destination MAC address.

Change of this parameter requires restart of the Knot server to take effect.

.. NOTE::
   This mode requires forwarding enabled on the loopback interface
   (``sysctl -w net.ipv4.conf.lo.forwarding=1`` and ``sysctl -w net.ipv6.conf.lo.forwarding=1``).
   If forwarding is disabled, all incoming DNS packets are dropped!

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

Maximum time (in seconds) the control socket operations can take.
Set to 0 for infinity.

*Default:* 5

.. _Logging section:

Logging section
===============

Server can be configured to log to the standard output, standard error
output, syslog (or systemd journal if systemd is enabled) or into an arbitrary
file.

There are 6 logging severity levels:

- ``critical`` – Non-recoverable error resulting in server shutdown.
- ``error`` – Recoverable error, action should be taken.
- ``warning`` – Warning that might require user action.
- ``notice`` – Server notice or hint.
- ``info`` – Informational message.
- ``debug`` – Debug or detailed message.

In the case of a missing log section, ``warning`` or more serious messages
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

- ``stdout`` – Standard output.
- ``stderr`` – Standard error output.
- ``syslog`` – Syslog or systemd journal.
- *file\_name* – A specific file.

With ``syslog`` target, syslog service is used. However, if Knot DNS has been compiled
with systemd support and operating system has been booted with systemd, systemd journal
is used for logging instead of syslog.

.. _log_server:

server
------

Minimum severity level for messages related to general operation of the server to be
logged.

*Default:* not set

.. _log_control:

control
-------

Minimum severity level for messages related to server control to be logged.

*Default:* not set

.. _log_zone:

zone
----

Minimum severity level for messages related to zones to be logged.

*Default:* not set

.. _log_any:

any
---

Minimum severity level for all message types to be logged.

*Default:* not set

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

.. _Database section:

Database section
================

Configuration of databases for zone contents, DNSSEC metadata, or event timers.

::

 database:
     storage: STR
     journal-db: STR
     journal-db-mode: robust | asynchronous
     journal-db-max-size: SIZE
     kasp-db: STR
     kasp-db-max-size: SIZE
     timer-db: STR
     timer-db-max-size: SIZE
     catalog-db: str
     catalog-db-max-size: SIZE

.. _database_storage:

storage
-------

A data directory for storing journal, KASP, and timer databases.

*Default:* ``${localstatedir}/lib/knot`` (configured with ``--with-storage=path``)

.. _database_journal-db:

journal-db
----------

An explicit specification of the persistent journal database directory.
Non-absolute path (i.e. not starting with ``/``) is relative to
:ref:`storage<database_storage>`.

*Default:* :ref:`storage<database_storage>`/journal

.. _database_journal-db-mode:

journal-db-mode
---------------

Specifies journal LMDB backend configuration, which influences performance
and durability.

Possible values:

- ``robust`` – The journal database disk sychronization ensures database
  durability but is generally slower.
- ``asynchronous`` – The journal database disk synchronization is optimized for
  better performance at the expense of lower database durability in the case of
  a crash. This mode is recommended on secondary servers with many zones.

*Default:* robust

.. _database_journal-db-max-size:

journal-db-max-size
-------------------

The hard limit for the journal database maximum size. There is no cleanup logic
in journal to recover from reaching this limit. Journal simply starts refusing
changes across all zones. Decreasing this value has no effect if it is lower
than the actual database file size.

It is recommended to limit :ref:`journal-max-usage<zone_journal-max-usage>`
per-zone instead of :ref:`journal-db-max-size<database_journal-db-max-size>`
in most cases. Please keep this value larger than the sum of all zones'
journal usage limits. See more details regarding
:ref:`journal behaviour<Journal behaviour>`.

.. NOTE::
   This value also influences server's usage of virtual memory.

*Default:* 20 GiB (512 MiB for 32-bit)

.. _database_kasp-db:

kasp-db
-------

An explicit specification of the KASP database directory.
Non-absolute path (i.e. not starting with ``/``) is relative to
:ref:`storage<database_storage>`.

*Default:* :ref:`storage<database_storage>`/keys

.. _database_kasp-db-max-size:

kasp-db-max-size
----------------

The hard limit for the KASP database maximum size.

.. NOTE::
   This value also influences server's usage of virtual memory.

*Default:* 500 MiB

.. _database_timer-db:

timer-db
--------

An explicit specification of the persistent timer database directory.
Non-absolute path (i.e. not starting with ``/``) is relative to
:ref:`storage<database_storage>`.

*Default:* :ref:`storage<database_storage>`/timers

.. _database_timer-db-max-size:

timer-db-max-size
-----------------

The hard limit for the timer database maximum size.

.. NOTE::
   This value also influences server's usage of virtual memory.

*Default:* 100 MiB

.. _database_catalog-db:

catalog-db
----------

An explicit specification of the zone catalog database directory.
Only useful if :ref:`catalog-zones` are enabled.
Non-absolute path (i.e. not starting with ``/``) is relative to
:ref:`storage<database_storage>`.

*Default:* :ref:`storage<database_storage>`/catalog

.. _database_catalog-db-max-size:

catalog-db-max-size
-------------------

The hard limit for the catalog database maximum size.

.. NOTE::
   This value also influences server's usage of virtual memory.

*Default:* 20 GiB (512 MiB for 32-bit)

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

A key storage backend type.

Possible values:

- ``pem`` – PEM files.
- ``pkcs11`` – PKCS #11 storage.

*Default:* pem

.. _keystore_config:

config
------

A backend specific configuration. A directory with PEM files (the path can
be specified as a relative path to :ref:`kasp-db<database_kasp-db>`) or
a configuration string for PKCS #11 storage (`<pkcs11-url> <module-path>`).

.. NOTE::
   Example configuration string for PKCS #11::

     "pkcs11:token=knot;pin-value=1234 /usr/lib64/pkcs11/libsofthsm2.so"

*Default:* :ref:`kasp-db<database_kasp-db>`/keys

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

.. NOTE::
   This value MUST be exactly the same as the name of the TSIG key on the
   opposite primary/secondary server(s).

.. _key_algorithm:

algorithm
---------

A TSIG key algorithm. See
`TSIG Algorithm Numbers <https://www.iana.org/assignments/tsig-algorithm-names/tsig-algorithm-names.xhtml>`_.

Possible values:

- ``hmac-md5``
- ``hmac-sha1``
- ``hmac-sha224``
- ``hmac-sha256``
- ``hmac-sha384``
- ``hmac-sha512``

*Default:* not set

.. _key_secret:

secret
------

Shared key secret.

*Default:* not set

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
     block-notify-after-transfer: BOOL

.. _remote_id:

id
--

A remote identifier.

.. _remote_address:

address
-------

An ordered list of destination IP addresses which are used for communication
with the remote server. The addresses are tried in sequence until the
remote is reached. Optional destination port (default is 53)
can be appended to the address using ``@`` separator.

*Default:* not set

.. NOTE::
   If the remote is contacted and it refuses to perform requested action,
   no more addresses will be tried for this remote.

.. _remote_via:

via
---

An ordered list of source IP addresses. The first address with the same family
as the destination address is used as a source address for communication with
the remote. This option can help if the server listens on more addresses.
Optional source port (default is random) can be appended
to the address using ``@`` separator.

*Default:* not set

.. _remote_key:

key
---

A :ref:`reference<key_id>` to the TSIG key which is used to authenticate
the communication with the remote server.

*Default:* not set

.. _remote_block-notify-after-transfer:

block-notify-after-transfer
---------------------------

When incoming AXFR/IXFR from this remote (as a primary server), suppress
sending NOTIFY messages to all configured secondary servers.

*Default:* off

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
     remote: remote_id ...
     action: notify | transfer | update ...
     deny: BOOL
     update-type: STR ...
     update-owner: key | zone | name
     update-owner-match: sub-or-equal | equal | sub
     update-owner-name: STR ...

.. _acl_id:

id
--

An ACL rule identifier.

.. _acl_address:

address
-------

An ordered list of IP addresses, network subnets, or network ranges. The query's
source address must match one of them. Empty value means that address match is not
required.

*Default:* not set

.. _acl_key:

key
---

An ordered list of :ref:`reference<key_id>`\ s to TSIG keys. The query must
match one of them. Empty value means that transaction authentication is not used.

*Default:* not set

.. _acl_remote:

remote
------

An ordered list of :ref:`references<remote_id>` to remotes. The query must
match one of the remotes. Specifically, one of the remote's addresses and remote's
TSIG key if configured must match.

.. NOTE::
   This option cannot be specified along with the :ref:`acl_address` or
   :ref:`acl_key` option at one ACL item.

*Default:* not set

.. _acl_action:

action
------

An ordered list of allowed (or denied) actions.

Possible values:

- ``notify`` – Allow incoming notify.
- ``transfer`` – Allow zone transfer.
- ``update`` – Allow zone updates.

*Default:* not set

.. _acl_deny:

deny
----

If enabled, instead of allowing, deny the specified :ref:`action<acl_action>`,
:ref:`address<acl_address>`, :ref:`key<acl_key>`, or combination if these
items. If no action is specified, deny all actions.

*Default:* off

.. _acl_update_type:

update-type
-----------

A list of allowed types of Resource Records in a zone update. Every record in an update
must match one of the specified types.

*Default:* not set

.. _acl_update_owner:

update-owner
------------

This option restricts possible owners of Resource Records in a zone update by comparing
them to either the :ref:`TSIG key<acl_key>` identity, the current zone name, or to a list of
domain names given by the :ref:`update-owner-name<acl_update_owner_name>` option.
The comparison method is given by the :ref:`update-owner-match<acl_update_owner_match>` option.

Possible values:

- ``key`` — The owner of each updated RR must match the identity of the TSIG key if used.
- ``name`` — The owner of each updated RR must match at least one name in the
  :ref:`update-owner-name<acl_update_owner_name>` list.
- ``zone`` — The owner of each updated RR must match the current zone name.

*Default:* not set

.. _acl_update_owner_match:

update-owner-match
------------------

This option defines how the owners of Resource Records in an update are matched to the domain name(s)
set by the :ref:`update-owner<acl_update_owner>` option.

Possible values:

- ``sub-or-equal`` — The owner of each Resource Record in an update must either be equal to
  or be a subdomain of at least one domain set by :ref:`update-owner<acl_update_owner>`.
- ``equal`` — The owner of each updated RR must be equal to at least one domain set by
  :ref:`update-owner<acl_update_owner>`.
- ``sub`` — The owner of each updated RR must be a subdomain of, but MUST NOT be equal to at least
  one domain set by :ref:`update-owner<acl_update_owner>`.

*Default:* sub-or-equal

.. _acl_update_owner_name:

update-owner-name
-----------------

A list of allowed owners of RRs in a zone update used with :ref:`update-owner<acl_update_owner>`
set to ``name``. Every listed owner name which is not FQDN (i.e. it doesn't end
in a dot) is considered as if it was appended with the target zone name.
Such a relative owner name specification allows better ACL rule reusability across
multiple zones.

*Default:* not set

.. _Submission section:

Submission section
==================

Parameters of KSK submission checks.

::

 submission:
   - id: STR
     parent: remote_id ...
     check-interval: TIME
     timeout: TIME

.. _submission_id:

id
--

A submission identifier.

.. _submission_parent:

parent
------

A list of :ref:`references<remote_id>` to parent's DNS servers to be checked for
presence of corresponding DS records in the case of KSK submission. All of them must
have a corresponding DS for the rollover to continue. If none is specified, the
rollover must be pushed forward manually.

*Default:* not set

.. TIP::
   A DNSSEC-validating resolver can be set as a parent.

.. _submission_check-interval:

check-interval
--------------

Interval for periodic checks of DS presence on parent's DNS servers, in the
case of the KSK submission.

*Default:* 1 hour

.. _submission_timeout:

timeout
-------

After this time period (in seconds) the KSK submission is automatically considered
successful, even if all the checks were negative or no parents are configured.
Set to 0 for infinity.

*Default:* 0

.. _Policy section:

Policy section
==============

DNSSEC policy configuration.

::

 policy:
   - id: STR
     keystore: keystore_id
     manual: BOOL
     single-type-signing: BOOL
     algorithm: rsasha1 | rsasha1-nsec3-sha1 | rsasha256 | rsasha512 | ecdsap256sha256 | ecdsap384sha384 | ed25519 | ed448
     ksk-size: SIZE
     zsk-size: SIZE
     ksk-shared: BOOL
     dnskey-ttl: TIME
     zone-max-ttl: TIME
     ksk-lifetime: TIME
     zsk-lifetime: TIME
     delete-delay: TIME
     propagation-delay: TIME
     rrsig-lifetime: TIME
     rrsig-refresh: TIME
     rrsig-pre-refresh: TIME
     reproducible-signing: BOOL
     nsec3: BOOL
     nsec3-iterations: INT
     nsec3-opt-out: BOOL
     nsec3-salt-length: INT
     nsec3-salt-lifetime: TIME
     signing-threads: INT
     ksk-submission: submission_id
     ds-push: remote_id
     cds-cdnskey-publish: none | delete-dnssec | rollover | always | double-ds
     cds-digest-type: sha256 | sha384
     offline-ksk: BOOL
     unsafe-operation: none | no-check-keyset | no-update-dnskey | no-update-nsec | no-update-expired ...

.. _policy_id:

id
--

A policy identifier.

.. _policy_keystore:

keystore
--------

A :ref:`reference<keystore_id>` to a keystore holding private key material
for zones.

*Default:* an imaginary keystore with all default values

.. NOTE::
   A configured keystore called "default" won't be used unless explicitly referenced.

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

*Default:* off (:ref:`module onlinesign<mod-onlinesign>` has default on)

.. _policy_algorithm:

algorithm
---------

An algorithm of signing keys and issued signatures. See
`DNSSEC Algorithm Numbers <https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1>`_.

Possible values:

- ``rsasha1``
- ``rsasha1-nsec3-sha1``
- ``rsasha256``
- ``rsasha512``
- ``ecdsap256sha256``
- ``ecdsap384sha384``
- ``ed25519``
- ``ed448``

.. NOTE::
   Ed25519 algorithm is only available if compiled with GnuTLS 3.6.0+.

   Ed448 algorithm is only available if compiled with GnuTLS 3.6.12+ and Nettle 3.6+.

*Default:* ecdsap256sha256

.. _policy_ksk-size:

ksk-size
--------

A length of newly generated :abbr:`KSK (Key Signing Key)` or
:abbr:`CSK (Combined Signing Key)` keys.

*Default:* 2048 (rsa*), 256 (ecdsap256), 384 (ecdsap384), 256 (ed25519), 456 (ed448)

.. _policy_zsk-size:

zsk-size
--------

A length of newly generated :abbr:`ZSK (Zone Signing Key)` keys.

*Default:* see default for :ref:`ksk-size<policy_ksk-size>`

.. _policy_ksk-shared:

ksk-shared
----------

If enabled, all zones with this policy assigned will share one or more KSKs.
More KSKs can be shared during a KSK rollover.

.. WARNING::
   As the shared KSK set is bound to the policy :ref:`id<policy_id>`, renaming the
   policy breaks this connection and new shared KSK set is initiated when
   a new KSK is needed.

*Default:* off

.. _policy_dnskey-ttl:

dnskey-ttl
----------

A TTL value for DNSKEY records added into zone apex.

.. NOTE::
   Has influence over ZSK key lifetime.

.. WARNING::
   Ensure all DNSKEYs with updated TTL are propagated before any subsequent
   DNSKEY rollover starts.

*Default:* zone SOA TTL

.. _policy_zone-max-ttl:

zone-max-ttl
------------

Declare (override) maximal TTL value among all the records in zone.

.. NOTE::
   It's generally recommended to override the maximal TTL computation by setting this
   explicitly whenever possible. It's required for :ref:`DNSSEC Offline KSK` and
   really reasonable when records are generated dynamically
   (e.g. by a :ref:`module<mod-synthrecord>`).

*Default:* computed after zone is loaded

.. _policy_ksk-lifetime:

ksk-lifetime
------------

A period between KSK activation and the next rollover initiation.

.. NOTE::
   KSK key lifetime is also influenced by propagation-delay, dnskey-ttl,
   and KSK submission delay.

   Zero (aka infinity) value causes no KSK rollover as a result.

   This applies for CSK lifetime if single-type-signing is enabled.

*Default:* 0

.. _policy_zsk-lifetime:

zsk-lifetime
------------

A period between ZSK activation and the next rollover initiation.

.. NOTE::
   More exactly, this period is measured since a ZSK is activated,
   and after this, a new ZSK is generated to replace it within
   following roll-over.

   ZSK key lifetime is also influenced by propagation-delay and dnskey-ttl

   Zero (aka infinity) value causes no ZSK rollover as a result.

*Default:* 30 days

.. _policy_delete-delay:

delete-delay
------------

Once a key (KSK or ZSK) is rolled-over and removed from the zone,
keep it in the KASP database for at least this period before deleting it completely.
This might be useful in some troubleshooting cases when resurrection
is needed.

*Default:* 0

.. _policy_propagation-delay:

propagation-delay
-----------------

An extra delay added for each key rollover step. This value should be high
enough to cover propagation of data from the primary server to all
secondary servers.

.. NOTE::
   Has influence over ZSK key lifetime.

*Default:* 1 hour

.. _policy_rrsig-lifetime:

rrsig-lifetime
--------------

A validity period of newly issued signatures.

.. NOTE::
   The RRSIG's signature inception time is set to 90 minutes in the past. This
   time period is not counted to the signature lifetime.

*Default:* 14 days

.. _policy_rrsig-refresh:

rrsig-refresh
-------------

A period how long at least before a signature expiration the signature will be refreshed,
in order to prevent expired RRSIGs on secondary servers or resolvers' caches.

*Default:* 7 days

.. _policy_rrsig-pre-refresh:

rrsig-pre-refresh
-----------------

A period how long at most before a signature refresh time the signature might be refreshed,
in order to refresh RRSIGs in bigger batches on a frequently updated zone
(avoid re-sign event too often).

*Default:* 1 hour

.. _policy_reproducible-signing:

reproducible-signing
--------------------

For ECDSA algorithms, generate RRSIG signatures deterministically (:rfc:`6979`).
Besides better theoretical cryptographic security, this mode allows significant
speed-up of loading signed (by the same method) zones. However, the zone signing
is a bit slower.

*Default:* off

.. _policy_nsec3:

nsec3
-----

Specifies if NSEC3 will be used instead of NSEC.

*Default:* off

.. _policy_nsec3-iterations:

nsec3-iterations
----------------

A number of additional times the hashing is performed.

*Default:* 10

.. _policy_nsec3-opt-out:

nsec3-opt-out
-------------

If set, NSEC3 records won't be created for insecure delegations.
This speeds up the zone signing and reduces overall zone size.

.. WARNING::
  NSEC3 with the Opt-Out bit set no longer works as a proof of non-existence
  in this zone.

*Default:* off

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

Zero value means infinity.

*Default:* 30 days

.. _policy_signing-threads:

signing-threads
---------------

When signing zone or update, use this number of threads for parallel signing.

Those are extra threads independent of :ref:`Background workers<server_background-workers>`.

.. NOTE::
   Some steps of the DNSSEC signing operation are not parallelized.

*Default:* 1 (no extra threads)

.. _policy_ksk-submission-check:

ksk-submission
--------------

A reference to :ref:`submission<submission_id>` section holding parameters of
KSK submission checks.

*Default:* not set

.. _policy_ds-push:

ds-push
-------

An optional :ref:`reference<remote_id>` to authoritative DNS server of the
parent's zone. The remote server must be configured to accept DS record
updates via DDNS. Whenever a CDS record in the local zone is changed, the
corresponding DS record is sent as a dynamic update (DDNS) to the parent
DNS server. All previous DS records are deleted within the DDNS message.
It's possible to manage both child and parent zones by the same Knot DNS server.

.. NOTE::
   This feature requires :ref:`cds-cdnskey-publish<policy_cds-cdnskey-publish>`
   not to be set to ``none``.

.. NOTE::
   Module :ref:`Onlinesign<mod-onlinesign>` doesn't support DS push.

*Default:* not set

.. _policy_cds-cdnskey-publish:

cds-cdnskey-publish
-------------------

Controls if and how shall the CDS and CDNSKEY be published in the zone.

Possible values:

- ``none`` – Never publish any CDS or CDNSKEY records in the zone.
- ``delete-dnssec`` – Publish special CDS and CDNSKEY records indicating turning off DNSSEC.
- ``rollover`` – Publish CDS and CDNSKEY records for ready and not yet active KSK (submission phase of KSK rollover).
- ``always`` – Always publish one CDS and one CDNSKEY records for the current KSK.
- ``double-ds`` – Always publish up to two CDS and two CDNSKEY records for ready and/or active KSKs.

.. NOTE::
   If the zone keys are managed manually, the CDS and CDNSKEY rrsets may contain
   more records depending on the keys available.

*Default:* rollover

.. _policy_cds-digest-type:

cds-digest-type
---------------

Specify digest type for published CDS records.

*Default:* sha256

.. _policy_offline-ksk:

offline-ksk
-----------

Specifies if :ref:`Offline KSK <DNSSEC Offline KSK>` feature is enabled.

*Default:* off

.. _policy_unsafe-operation:

unsafe-operation
----------------

Turn off some DNSSEC safety features.

Possible values:

- ``none`` – Nothing disabled.
- ``no-check-keyset`` – Don't check active keys in present algorithms. This may
  lead to violation of :rfc:`4035#section-2.2`.
- ``no-update-dnskey`` – Don't maintain/update DNSKEY, CDNSKEY, and CDS records
  in the zone apex according to KASP database. Juste leave them as they are in the zone.
- ``no-update-nsec`` – Don't maintain/update NSEC/NSEC3 chain. Leave all the records
  as they are in the zone.
- ``no-update-expired`` – Don't update expired RRSIGs.

Multiple values may be specified.

.. WARNING::
   This mode is intended for DNSSEC experts who understand the corresponding consequences.

*Default:* none

.. _Template section:

Template section
================

A template is shareable zone settings, which can simplify configuration by
reducing duplicates. A special default template (with the *default* identifier)
can be used for global zone configuration or as an implicit configuration
if a zone doesn't have another template specified.

::

 template:
   - id: STR
     global-module: STR/STR ...
     # All zone options (excluding 'template' item)

.. _template_id:

id
--

A template identifier.

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
     zonefile-sync: TIME
     zonefile-load: none | difference | difference-no-serial | whole
     journal-content: none | changes | all
     journal-max-usage: SIZE
     journal-max-depth: INT
     zone-max-size : SIZE
     adjust-threads: INT
     dnssec-signing: BOOL
     dnssec-validation: BOOL
     dnssec-policy: policy_id
     zonemd-verify: BOOL
     zonemd-generate: none | zonemd-sha384 | zonemd-sha512 | remove
     serial-policy: increment | unixtime | dateserial
     refresh-min-interval: TIME
     refresh-max-interval: TIME
     catalog-role: none | interpret | generate | member
     catalog-template: template_id ...
     catalog-zone: DNAME
     catalog-group: STR
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

A data directory for storing zone files.

*Default:* ``${localstatedir}/lib/knot`` (configured with ``--with-storage=path``)

.. _zone_file:

file
----

A path to the zone file. Non-absolute path (i.e. not starting with ``/``) is
relative to :ref:`storage<zone_storage>`.
It is also possible to use the following formatters:

- ``%c[``\ *N*\ ``]`` or ``%c[``\ *N*\ ``-``\ *M*\ ``]`` – Means the *N*\ th
  character or a sequence of characters beginning from the *N*\ th and ending
  with the *M*\ th character of the textual zone name (see ``%s``). The
  indexes are counted from 0 from the left. All dots (including the terminal
  one) are considered. If the character is not available, the formatter has no effect.
- ``%l[``\ *N*\ ``]`` – Means the *N*\ th label of the textual zone name
  (see ``%s``). The index is counted from 0 from the right (0 ~ TLD).
  If the label is not available, the formatter has no effect.
- ``%s`` – Means the current zone name in the textual representation.
  The zone name doesn't include the terminating dot (the result for the root
  zone is the empty string!).
- ``%%`` – Means the ``%`` character.

.. WARNING::
  Beware of special characters which are escaped or encoded in the \\DDD form
  where DDD is corresponding decimal ASCII code.

*Default:* :ref:`storage<zone_storage>`/``%s``\ .zone

.. _zone_master:

master
------

An ordered list of :ref:`references<remote_id>` to zone primary servers
(formerly known as master servers).

*Default:* not set

.. _zone_ddns-master:

ddns-master
-----------

A :ref:`reference<remote_id>` to zone primary master. If not specified,
the first :ref:`master<zone_master>` server is used.

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

If enabled, extra zone semantic checks are turned on.

Several checks are enabled by default and cannot be turned off. An error in
mandatory checks causes zone not to be loaded. An error in extra checks is
logged only.

Mandatory checks:

- SOA record missing in the zone (:rfc:`1034`)
- An extra record together with CNAME record except for RRSIG and DS (:rfc:`1034`)
- Multiple CNAME record with the same owner
- DNAME record having a record under it (:rfc:`2672`)

Extra checks:

- Missing NS record at the zone apex
- Missing glue A or AAAA record
- Invalid DNSKEY, DS, or NSEC3PARAM record
- CDS or CDNSKEY inconsistency
- Missing, invalid, or unverifiable RRSIG record
- Invalid NSEC(3) record
- Broken or non-cyclic NSEC(3) chain

*Default:* off

.. _zone_zonefile-sync:

zonefile-sync
-------------

The time after which the current zone in memory will be synced with a zone file
on the disk (see :ref:`file<zone_file>`). The server will serve the latest
zone even after a restart using zone journal, but the zone file on the disk will
only be synced after ``zonefile-sync`` time has expired (or after manual zone
flush). This is applicable when the zone is updated via IXFR, DDNS or automatic
DNSSEC signing. In order to completely disable automatic zone file synchronization,
set the value to -1. In that case, it is still possible to force a manual zone flush
using the ``-f`` option.

.. NOTE::
   If you are serving large zones with frequent updates where
   the immediate sync with a zone file is not desirable, increase the value.

*Default:* 0 (immediate)

.. _zone_zonefile-load:

zonefile-load
-------------

Selects how the zone file contents are applied during zone load.

Possible values:

- ``none`` – The zone file is not used at all.
- ``difference`` – If the zone contents are already available during server start or reload,
  the difference is computed between them and the contents of the zone file. This difference
  is then checked for semantic errors and applied to the current zone contents.
- ``difference-no-serial`` – Same as ``difference``, but the SOA serial in the zone file is
  ignored, the server takes care of incrementing the serial automatically.
- ``whole`` – Zone contents are loaded from the zone file.

When ``difference`` is configured and there are no zone contents yet (cold start
and no zone contents in the journal), it behaves the same way as ``whole``.

*Default:* whole

.. _zone_journal-content:

journal-content
---------------

Selects how the journal shall be used to store zone and its changes.

Possible values:

- ``none`` – The journal is not used at all.
- ``changes`` – Zone changes history is stored in journal.
- ``all`` – Zone contents and history is stored in journal.

*Default:* changes

.. _zone_journal-max-usage:

journal-max-usage
-----------------

Policy how much space in journal DB will the zone's journal occupy.

.. NOTE::
   Journal DB may grow far above the sum of journal-max-usage across
   all zones, because of DB free space fragmentation.

*Default:* 100 MiB

.. _zone_journal-max-depth:

journal-max-depth
-----------------

Maximum history length of the journal.

.. NOTE::
   Zone-in-journal changeset isn't counted to the limit.

*Minimum:* 2

*Default:* 20

.. _zone_zone-max-size:

zone-max-size
-------------

Maximum size of the zone. The size is measured as size of the zone records
in wire format without compression. The limit is enforced for incoming zone
transfers and dynamic updates.

For incremental transfers (IXFR), the effective limit for the total size of
the records in the transfer is twice the configured value. However the final
size of the zone must satisfy the configured value.

*Default:* 2^64

.. _zone_adjust-threads:

adjust-threads
--------------

Parallelize internal zone adjusting procedures. This is useful with huge
zones with NSEC3. Speedup observable at server startup and while processing
NSEC3 re-salt.

*Default:* 1

.. _zone_dnssec-signing:

dnssec-signing
--------------

If enabled, automatic DNSSEC signing for the zone is turned on.

*Default:* off

.. _zone_dnssec-validation:

dnssec-validation
-----------------

If enabled, the zone contents are validated for being correctly signed
(including NSEC/NSEC3 chain) with DNSSEC signatures every time the zone
is loaded or changed (including AXFR/IXFR).

When the validation fails, the zone being loaded or update being applied
is cancelled with an error, and either none or previous zone state is published.

List of DNSSEC checks:

- Every zone RRSet is correctly signed by at least one present DNSKEY.
- DNSKEY RRSet is signed by KSK.
- NSEC(3) RR exists for each name (unless opt-out) with correct bitmap.
- Every NSEC(3) RR is linked to the lexicographically next one.

The validation is not affected by :ref:`zone_dnssec-policy` configuration,
except for :ref:`policy_signing-threads` option, which specifies the number
of threads for parallel validation.

.. NOTE::

   Redundant or garbage NSEC3 records are ignored.

   This mode is not compatible with :ref:`zone_dnssec-signing`.

.. _zone_dnssec-policy:

dnssec-policy
-------------

A :ref:`reference<policy_id>` to DNSSEC signing policy.

*Default:* an imaginary policy with all default values

.. NOTE::
   A configured policy called "default" won't be used unless explicitly referenced.

.. _zone_zonemd-verify:

zonemd-verify
-------------

On each zone load/update, verify that ZONEMD is present in the zone and valid.

.. NOTE::
   Zone digest calculation may take much time and CPU on large zones.

*Default:* off

.. _zone_zonemd-generate:

zonemd-generate
---------------

On each zone update, calculate ZONEMD and put it into the zone.

Possible values:

- ``none`` – No action regarding ZONEMD.
- ``zonemd-sha384`` – Generate ZONEMD using SHA384 algorithm.
- ``zonemd-sha512`` – Generate ZONEMD using SHA512 algorithm.
- ``remove`` – Remove any ZONEMD from the zone apex.

*Default:* none

.. _zone_serial-policy:

serial-policy
-------------

Specifies how the zone serial is updated after a dynamic update or
automatic DNSSEC signing. If the serial is changed by the dynamic update,
no change is made.

Possible values:

- ``increment`` – The serial is incremented according to serial number arithmetic.
- ``unixtime`` – The serial is set to the current unix time.
- ``dateserial`` – The 10-digit serial (YYYYMMDDnn) is incremented, the first
  8 digits match the current iso-date.

.. NOTE::
   If the resulting serial for ``unixtime`` or ``dateserial`` is lower or equal
   than the current serial (this happens e.g. when migrating from other policy or
   frequent updates), the serial is incremented instead.

   To avoid user confusion, use ``dateserial`` only if you expect at most
   100 updates per day per zone and ``unixtime`` only if you expect at most
   one update per second per zone.

*Default:* increment

.. _zone_refresh-min-interval:

refresh-min-interval
--------------------

Forced minimum zone refresh interval to avoid flooding primary server.

*Default:* 2

.. _zone_refresh-max-interval:

refresh-max-interval
--------------------

Forced maximum zone refresh interval.

*Default:* not set

.. _zone_catalog-role:

catalog-role
------------

Trigger zone catalog feature. Possible values:

- ``none`` – Not a catalog zone.
- ``interpret`` – A catalog zone which is loaded from a zone file or XFR,
  and member zones shall be configured based on its contents.
- ``generate`` – A catalog zone whose contents are generated according to
  assigned member zones.
- ``member`` – A member zone that is assigned to one generated catalog zone.

*Default:* none

.. _zone_catalog-template:

catalog-template
----------------

For the catalog member zones, the specified configuration template will be applied.

Multiple catalog templates may be defined. The first one is used unless the member zone
has the *group* property defined, matching another catalog template.

.. NOTE::
   This option must be set if and only if :ref:`zone_catalog-role` is *interpret*.

*Default:* not set

.. _zone_catalog-zone:

catalog-zone
------------

Assign this member zone to specified generated catalog zone.

.. NOTE::
   This option must be set if and only if :ref:`zone_catalog-role` is *member*.

   The referenced catalog zone must exist and have :ref:`zone_catalog-role` set to *generate*.

*Default:* not set

.. _zone_catalog-group:

catalog-group
-------------

Assign this member zone to specified catalog group (configuration template).

.. NOTE::
   This option has effect if and only if :ref:`zone_catalog-role` is *member*.

*Default:* not set

.. _zone_module:

module
------

An ordered list of references to query modules in the form of *module_name* or
*module_name/module_id*. These modules apply only to the current zone queries.

*Default:* not set
