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
        slip: 2           # Every other response slips

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
     whitelist: ADDR[/INT] | ADDR-ADDR ...

.. _mod-rrl_id:

id
..

A module identifier.

.. _mod-rrl_rate-limit:

rate-limit
..........

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
..........

Size of the hash table in a number of buckets. The larger the hash table, the lesser
the probability of a hash collision, but at the expense of additional memory costs.
Each bucket is estimated roughly to 32 bytes. The size should be selected as
a reasonably large prime due to better hash function distribution properties.
Hash table is internally chained and works well up to a fill rate of 90 %, general
rule of thumb is to select a prime near 1.2 * maximum_qps.

*Default:* 393241

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
.........

A list of IP addresses, network subnets, or network ranges to exempt from
rate limiting. Empty list means that no incoming connection will be
white-listed.

*Default:* not set
