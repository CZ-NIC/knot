.. _mod-rrl:

``rrl`` — Response rate limiting
================================

Response rate limiting (RRL) is a method to combat DNS reflection amplification
attacks. These attacks rely on the fact that the source address of a UDP query
can be forged, and without a worldwide deployment of `BCP38
<https://tools.ietf.org/html/bcp38>`_, such a forgery cannot be prevented.
An attacker can use a DNS server (or multiple servers) as an amplification
source to flood a victim with a large number of unsolicited DNS responses.
RRL lowers the amplification factor of these attacks by sending some
responses as truncated or by dropping them altogether.

This module can also help protect the server from excessive utilization by
limiting incoming packets (including handshakes) based on consumed time.
If a packet is time rate limited, it's dropped. This function works with
all supported non-UDP transport protocols (TCP, TLS, and QUIC) and cannot
be configured per zone.

.. NOTE::
   This module introduces three statistics counters:

   - ``slipped`` – The number of slipped UDP responses.
   - ``dropped`` – The number of dropped UDP responses due to the rate limit.
   - ``dropped-time`` – The number of dropped non-UDP packets due to the time rate limit.

.. NOTE::
   If the :ref:`Cookies<mod-cookies>` module is active, RRL is not applied
   to UDP responses with a valid DNS cookie.

.. NOTE::
   The time limiting applies even to handshakes of incoming authorized requests
   (e.g. NOTIFY, AXFR). In such cases, setting :ref:`mod-rrl_whitelist` or reusing
   already established connections (e.g. :ref:`server_remote-pool-timeout` on
   the remote server) can mitigate this issue.

Example
-------

You can enable RRL by setting the module globally

::

    template:
      - id: default
        global-module: mod-rrl  # Default module configuration

or per zone

::

    mod-rrl:
      - id: custom
        rate-limit: 200

    zone:
      - domain: example.com
        module: mod-rrl/custom  # Custom module configuration

Module reference
----------------

::

 mod-rrl:
   - id: STR
     rate-limit: INT
     instant-limit: INT
     slip: INT
     time-rate-limit: INT
     time-instant-limit: INT
     table-size: INT
     whitelist: ADDR[/INT] | ADDR-ADDR | STR ...
     log-period: INT
     dry-run: BOOL

.. _mod-rrl_id:

id
..

A module identifier.

.. _mod-rrl_rate-limit:

rate-limit
..........

Maximal allowed number of UDP queries per second from a single IPv6 or IPv4 address.

Rate limiting is performed for the whole address and several chosen prefixes.
The limits of prefixes are constant multiples of :ref:`mod-rrl_rate-limit`.

The specific prefixes and multipliers, which might be adjusted in the future, are
for IPv6 /128: 1, /64: 2, /56: 3, /48: 4, /32: 64;
for IPv4 /32: 1, /24: 32, /20: 256, /18: 768.

With each host/network, a counter of unrestricted responses is associated;
if the counter would exceed its capacity, it is not incremented and the response is restricted.
Counters use exponential decay for lowering their values,
i.e. they are lowered by a constant fraction of their value each millisecond.
The specified rate limit is reached, when the number of queries is the same every millisecond;
sending many queries once a second or even a larger timespan leads to a more strict limiting.

Set to 0 to disable the rate limiting.

*Default:* ``50``

.. _mod-rrl_instant-limit:

instant-limit
.............

Maximal allowed number of queries at a single point in time from a single IPv6 or IPv4 address.
The limits for prefixes use the same multipliers as for :ref:`mod-rrl_rate-limit`.

This limit is reached when many queries come from a new host/network,
or after a longer time of inactivity.

The :ref:`mod-rrl_instant-limit` sets the actual capacity of each counter of responses,
and together with the :ref:`mod-rrl_rate-limit` they set the fraction by which the counter
is periodically lowered.
The :ref:`mod-rrl_instant-limit` may be at least :ref:`mod-rrl_rate-limit` **/ 1000**, at which point the
counters are zeroed each millisecond.

*Default:* ``125``

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

.. _mod-rrl_time-rate-limit:

time-rate-limit
...............

This limit works similarly to :ref:`mod-rrl_rate-limit` but considers the time
consumed (in microseconds) by the remote over non-UDP transport protocols.

Set to 0 to disable the time limiting.

*Default:* ``5000`` (microseconds)

.. _mod-rrl_time-instant-limit:

time-instant-limit
..................

This limit works similarly to :ref:`mod-rrl_instant-limit` but considers the time
consumed (in microseconds) by the remote over non-UDP transport protocols.

*Default:* ``5000`` (microseconds)

.. _mod-rrl_table-size:

table-size
..........

Maximal number of stored hosts/networks with their counters.
The data structure tries to store only the most frequent sources,
so it is safe to set it according to the expected maximal number of limited ones.

Use `1.4 * maximum_qps / rate-limit`,
where `maximum_qps` is the number of queries which can be handled by the server per second.
There is at most `maximum_qps / rate-limit` limited hosts;
larger networks have higher limits and so require only a fraction of the value (handled by the `1.4` multiplier).
The value will be rounded up to the nearest power of two.

The same table size is used for both counting-based and time-based limiting;
the maximum number of time-limited hosts is expected to be lower, so it's not typically needed to be considered.
There is at most `1 000 000 * #cpus / time-rate-limit` of them.

The memory occupied by one table structure is `8 * table-size B`.

*Default:* ``524288``

.. _mod-rrl_whitelist:

whitelist
.........

An ordered list of IP addresses, absolute UNIX socket paths, network subnets,
or network ranges to exempt from rate limiting.
Empty list means that no incoming connection will be white-listed.

*Default:* not set

.. _mod-rrl_log-period:

log-period
..........

Minimal time in milliseconds between two log messages,
or zero to disable logging.

If a response is limited, the address and the prefix on which it was blocked is logged
and logging is disabled for the `log-period` milliseconds.
As long as limiting is needed, one source is logged each period
and sources with more blocked queries have greater probability to be chosen.

The approach is used by counting-based and time-based limiting separately,
so you can expect one message per `log-period` from each of them.

*Default:* ``30000`` (milliseconds)

.. _mod-rrl_dry-run:

dry-run
.......

If enabled, the module doesn't alter any response. Only query classification
is performed with possible statistics counter incrementation.

*Default:* ``off``
