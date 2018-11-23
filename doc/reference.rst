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

There are 12 main sections (``module``, ``server``, ``control``, ``log``,
``statistics``, ``keystore``, ``policy``, ``key``, ``acl``, ``remote``,
``template``, and ``zone``) and module sections with the ``mod-`` prefix.
Most of the sections (excluding ``server``, ``control``, and ``statistics``)
are sequences of settings blocks. Each settings block begins with a unique identifier,
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

*Default:* ``${libdir}/knot/modules-${version}``/module_name.so
(or ``${path}``/module_name.so if configured with ``--with-moduledir=path``)

.. WARNING::
   If the path is not absolute, the library is searched in the set of
   system directories. See ``man dlopen`` for more details.

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
     edns-client-subnet: BOOL
     answer-rotation: BOOL
     listen: ADDR[@INT] ...

.. _server_identity:

identity
--------

An identity of the server returned in the response to the query for TXT
record ``id.server.`` or ``hostname.bind.`` in the CHAOS class (:rfc:`4892`).
Set empty value to disable.

*Default:* FQDN hostname

.. _server_version:

version
-------

A version of the server software returned in the response to the query
for TXT record ``version.server.`` or ``version.bind.`` in the CHAOS
class (:rfc:`4892`). Set empty value to disable.

*Default:* server version

.. _server_nsid:

nsid
----

A DNS name server identifier (:rfc:`5001`). Set empty value to disable.

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

.. NOTE::
   This value MUST be exactly the same as the name of the TSIG key on the
   opposite master/slave server(s).

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

An ordered list of IP addresses, network subnets, or network ranges. The query
must match one of them. Empty value means that address match is not required.

*Default:* not set

.. _acl_key:

key
---

An ordered list of :ref:`reference<key_id>`\ s to TSIG keys. The query must
match one of them. Empty value means that transaction authentication is not used.

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
set to ``name``.

*Default:* not set

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

A key storage backend type.

Possible values:

- ``pem`` – PEM files.
- ``pkcs11`` – PKCS #11 storage.

*Default:* pem

.. _keystore_config:

config
------

A backend specific configuration. A directory with PEM files (the path can
be specified as a relative path to :ref:`kasp-db<template_kasp-db>`) or
a configuration string for PKCS #11 storage (`<pkcs11-url> <module-path>`).

.. NOTE::
   Example configuration string for PKCS #11::

     "pkcs11:token=knot;pin-value=1234 /usr/lib64/pkcs11/libsofthsm2.so"

*Default:* :ref:`kasp-db<template_kasp-db>`/keys

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

After this period, the KSK submission is automatically considered successful, even
if all the checks were negative or no parents are configured. Set 0 for infinity.

*Default:* 0

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
     algorithm: rsasha1 | rsasha1-nsec3-sha1 | rsasha256 | rsasha512 | ecdsap256sha256 | ecdsap384sha384 | ed25519
     ksk-size: SIZE
     zsk-size: SIZE
     ksk-shared: BOOL
     dnskey-ttl: TIME
     zone-max-ttl: TIME
     zsk-lifetime: TIME
     ksk-lifetime: TIME
     propagation-delay: TIME
     rrsig-lifetime: TIME
     rrsig-refresh: TIME
     nsec3: BOOL
     nsec3-iterations: INT
     nsec3-opt-out: BOOL
     nsec3-salt-length: INT
     nsec3-salt-lifetime: TIME
     ksk-submission: submission_id
     cds-cdnskey-publish: none | delete-dnssec | rollover | always | double-ds
     offline-ksk: BOOL

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

*Default:* off

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

*Default:* ecdsap256sha256

.. NOTE::
   Ed25519 algorithm is only available when compiled with GnuTLS 3.6.0+.

.. _policy_ksk-size:

ksk-size
--------

A length of newly generated :abbr:`KSK (Key Signing Key)` or
:abbr:`CSK (Combined Signing Key)` keys.

*Default:* 2048 (rsa*), 256 (ecdsap256), 384 (ecdsap384), 256 (ed25519)

.. _policy_zsk-size:

zsk-size
--------

A length of newly generated :abbr:`ZSK (Zone Signing Key)` keys.

*Default:* see default for :ref:`ksk-size<policy_ksk-size>`

.. _policy_ksk-shared:

ksk-shared
----------

If enabled, all zones with this policy assigned will share one KSK.

*Default:* off

.. _policy_dnskey-ttl:

dnskey-ttl
----------

A TTL value for DNSKEY records added into zone apex.

*Default:* zone SOA TTL

.. NOTE::
   Has infuence over ZSK key lifetime.

.. _policy_zone-max-ttl:

zone-max-ttl
------------

Maximal TTL value among all the records in zone.

.. NOTE::
   It's generally recommended to override the maximal TTL computation by setting this
   explicitly whenever possible. It's required for :ref:`DNSSEC Offline KSK`.

*Default:* computed after zone is loaded

.. _policy_zsk-lifetime:

zsk-lifetime
------------

A period between ZSK publication and the next rollover initiation.

*Default:* 30 days

.. NOTE::
   ZSK key lifetime is also infuenced by propagation-delay and dnskey-ttl

   Zero (aka infinity) value causes no ZSK rollover as a result.

.. _policy_ksk-lifetime:

ksk-lifetime
------------

A period between KSK publication and the next rollover initiation.

*Default:* 0

.. NOTE::
   KSK key lifetime is also infuenced by propagation-delay, dnskey-ttl,
   and KSK submission delay.

   Zero (aka infinity) value causes no KSK rollover as a result.

   This applies for CSK lifetime if single-type-signing is enabled.

.. _policy_propagation-delay:

propagation-delay
-----------------

An extra delay added for each key rollover step. This value should be high
enough to cover propagation of data from the master server to all slaves.

*Default:* 1 hour

.. NOTE::
   Has infuence over ZSK key lifetime.

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

*Default:* 30 days

.. _policy_ksk-submission-check:

ksk-submission
--------------

A reference to :ref:`submission<submission_id>` section holding parameters of
KSK submittion checks.

*Default:* not set

.. _policy_cds-cdnskey-publish:

cds-cdnskey-publish
-------------------

Controls if and how shall the CDS and CDNSKEY be published in the zone.

Possible values:

- ``none`` – Never publish any CDS or CDNSKEY records in the zone.
- ``delete-dnssec`` – Publish special CDS and CDNSKEY records indicating turning off DNSSEC.
- ``rollover`` – Publish CDS and CDNSKEY records only in the submission phase of KSK rollover.
- ``always`` – Always publish one CDS and one CDNSKEY records for the current KSK.
- ``double-ds`` – Always publish up to two CDS and two CDNSKEY records for ready and/or active KSKs.

.. NOTE::
   If the zone keys are managed manually, the CDS and CDNSKEY rrsets may contain
   more records depending on the keys available.

*Default:* always

.. _policy_offline-ksk:

offline-ksk
-----------

Specifies if :ref:`Offline KSK <DNSSEC Offline KSK>` feature is enabled.

*Default:* off

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
     max-timer-db-size: SIZE
     journal-db: STR
     journal-db-mode: robust | asynchronous
     max-journal-db-size: SIZE
     kasp-db: STR
     max-kasp-db-size: SIZE
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

.. _template_max-timer-db-size:

max-timer-db-size
-----------------

Hard limit for the timer database maximum size.

.. NOTE::
   This option is only available in the *default* template.

*Default:* 100 MiB

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
  generally slower.
- ``asynchronous`` – The journal DB disk synchronization is optimized for
  better performance at the expense of lower DB durability; this mode is
  recommended only on slave nodes with many zones.

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
larger than the sum of all zones' journal usage limits. See more details
regarding :ref:`journal behaviour<Journal behaviour>`.

This value also influences server's usage of virtual memory.

.. NOTE::
   This option is only available in the *default* template.

*Default:* 20 GiB (1 GiB for 32-bit)

.. _template_kasp-db:

kasp-db
-------

A KASP database path. Non-absolute path is relative to
:ref:`storage<zone_storage>`.

*Default:* :ref:`storage<zone_storage>`/keys

.. NOTE::
   This option is only available in the *default* template.

.. _template_max-kasp-db-size:

max-kasp-db-size
----------------

Hard limit for the KASP database maximum size.

.. NOTE::
   This option is only available in the *default* template.

*Default:* 500 MiB

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
     zonefile-load: none | difference | difference-no-serial | whole
     journal-content: none | changes | all
     max-journal-usage: SIZE
     max-journal-depth: INT
     max-zone-size : SIZE
     dnssec-signing: BOOL
     dnssec-policy: STR
     request-edns-option: INT:[HEXSTR]
     serial-policy: increment | unixtime | dateserial
     min-refresh-interval: TIME
     max-refresh-interval: TIME
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

A data directory for storing zone files, journal database, and timers database.

*Default:* ``${localstatedir}/lib/knot`` (configured with ``--with-storage=path``)

.. _zone_file:

file
----

A path to the zone file. Non-absolute path is relative to
:ref:`storage<zone_storage>`. It is also possible to use the following formatters:

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
  is then checked for semantic errors and
  applied to the current zone contents.
- ``difference-no-serial`` – Same as ``difference``, but the SOA serial in the zone file is
  ignored, the server takes care of incrementing the serial automatically.
- ``whole`` – Zone contents are loaded from the zone file.

When ``difference`` is configured and there are no zone contents yet (cold start of Knot
and no zone contents in journal), it behaves the same way like ``whole``.

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

*Minimum:* 2

*Default:* 2^64

.. _zone_max_zone_size:

max-zone-size
-------------

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

*Default:* off

.. _zone_dnssec-policy:

dnssec-policy
-------------

A :ref:`reference<policy_id>` to DNSSEC signing policy. A special *default*
value can be used for the default policy settings.

*Required*

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

- ``increment`` – The serial is incremented according to serial number arithmetic.
- ``unixtime`` – The serial is set to the current unix time.
- ``dateserial`` – The 10-digit serial (YYYYMMDDnn) is incremented, the first
  8 digits match the current iso-date.

.. NOTE::
   In case of ``unixtime``, if the resulting serial is lower or equal than current zone
   (this happens e.g. in case of migrating from other policy or frequent updates)
   the serial is incremented instead.

   Use dateserial only if you expect less than 100 updates per day per zone.

*Default:* increment

.. _zone_min-refresh-interval:

min-refresh-interval
--------------------

Forced minimum zone refresh interval to avoid flooding master.

*Default:* 2

.. _zone_max-refresh-interval:

max-refresh-interval
--------------------

Forced maximum zone refresh interval.

*Default:* not set

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

- ``critical`` – Non-recoverable error resulting in server shutdown.
- ``error`` – Recoverable error, action should be taken.
- ``warning`` – Warning that might require user action.
- ``notice`` – Server notice or hint.
- ``info`` – Informational message.
- ``debug`` – Debug messages (must be turned on at compile time).

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

- ``stdout`` – Standard output.
- ``stderr`` – Standard error output.
- ``syslog`` – Syslog.
- *file\_name* – A specific file.

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
