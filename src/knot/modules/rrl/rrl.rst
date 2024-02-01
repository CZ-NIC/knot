.. _mod-rrl:

``rrl`` — Response rate limiting
================================

Response rate limiting (RRL) is a method to combat DNS reflection amplification
attacks. These attacks rely on the fact that source address of a UDP query
can be forged, and without a worldwide deployment of `BCP38
<https://tools.ietf.org/html/bcp38>`_, such a forgery cannot be prevented.
An attacker can use a DNS server (or multiple servers) as an amplification
source and can flood a victim with a large number of unsolicited DNS responses.
The RRL lowers the amplification factor of these attacks by sending some of
the responses as truncated or by dropping them altogether.

.. NOTE::
   The module introduces two statistics counters. The number of slipped and
   dropped responses.

.. NOTE::
   If the :ref:`Cookies<mod-cookies>` module is active, RRL is not applied
   for responses with a valid DNS cookie.

Example
-------

You can enable RRL by setting the module globally or per zone.

::

    mod-rrl:
      - id: default
        rate-limit: 200   # Allow 200 resp/s for each flow
        slip: 2           # Approximately every other response slips

    template:
      - id: default
        global-module: mod-rrl/default   # Enable RRL globally

Module reference
----------------

::

 mod-rrl:
   - id: STR
     rate-limit: INT
     slip: INT
     table-size: INT
     whitelist: ADDR[/INT] | ADDR-ADDR | STR ...

.. _mod-rrl_id:

id
..

A module identifier.

.. _mod-rrl_rate-limit:

rate-limit
..........

Maximal allowed number of queries per second from a single host.

Rate limiting is performed on the whole address and several chosen prefixes.
The limits of prefixes are constant multiples of `rate-limit`.

*Required*

.. _mod-rrl_table-size:

table-size
..........

Maximal number of stored hosts/networks with their current frequencies of queries.
The data structure tries to store only the most frequent sources and the table size is internally a little bigger,
so it is safe to set it according to the expected maximal number of limited sources.

Use `4 * maximum_qps / rate-limit`,
where `maximum_qps` is the number of queries which can be handled by the server per second.
There is at most `maximum_qps / rate-limit` limited sources for each of `4` prefixes.
The value will be rounded up to the nearest power of two.

The memory occupied by the data structure is `8 * table-size B`.

*Default:* ``524288``

.. _mod-rrl_slip:

slip
....

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

- Setting the value to **2** will cause that approximately half of the rate-limited responses
  will be dropped, the other half will be sent as truncated. With this
  configuration, both outbound bandwidth and packet rate will be lower than the
  inbound. On the other hand, the dropped responses enlarge the time window
  for possible cache poisoning attack on the resolver.

- Setting the value to anything **larger than 2** will keep on decreasing
  the outgoing rate-limited bandwidth, packet rate, and chances to notify
  legitimate requestors to reconnect using TCP. These attributes are inversely
  proportional to the configured value. Setting the value high is not advisable.

*Default:* ``1``

.. _mod-rrl_whitelist:

whitelist
.........

An ordered list of IP addresses, absolute UNIX socket paths, network subnets,
or network ranges to exempt from rate limiting.
Empty list means that no incoming connection will be white-listed.

*Default:* not set
