.. _mod-whoami:

``whoami`` — Whoami response
============================

The module synthesizes an A or AAAA record containing the query source IP address,
at the apex of the zone being served. It makes sure to allow Knot DNS to generate
cacheable negative responses, and to allow fallback to extra records defined in the
underlying zone file. The TTL of the synthesized record is copied from
the TTL of the SOA record in the zone file.

Because a DNS query for type A or AAAA has nothing to do with whether
the query occurs over IPv4 or IPv6, this module requires a special
zone configuration to support both address families. For A queries, the
underlying zone must have a set of nameservers that only have IPv4
addresses, and for AAAA queries, the underlying zone must have a set of
nameservers that only have IPv6 addresses.

Example
-------

To enable this module, you need to add something like the following to
the Knot DNS configuration file::

    zone:
      - domain: whoami.domain.example
        file: "/path/to/whoami.domain.example"
        module: mod-whoami

    zone:
      - domain: whoami6.domain.example
        file: "/path/to/whoami6.domain.example"
        module: mod-whoami

The whoami.domain.example zone file example:

  .. code-block:: none

    $TTL 1

    @       SOA     (
                            whoami.domain.example.          ; MNAME
                            hostmaster.domain.example.      ; RNAME
                            2016051300                      ; SERIAL
                            86400                           ; REFRESH
                            86400                           ; RETRY
                            86400                           ; EXPIRE
                            1                               ; MINIMUM
                    )

    $TTL 86400

    @       NS      ns1.whoami.domain.example.
    @       NS      ns2.whoami.domain.example.
    @       NS      ns3.whoami.domain.example.
    @       NS      ns4.whoami.domain.example.

    ns1     A       198.51.100.53
    ns2     A       192.0.2.53
    ns3     A       203.0.113.53
    ns4     A       198.19.123.53

The whoami6.domain.example zone file example:

  .. code-block:: none

    $TTL 1

    @       SOA     (
                            whoami6.domain.example.         ; MNAME
                            hostmaster.domain.example.      ; RNAME
                            2016051300                      ; SERIAL
                            86400                           ; REFRESH
                            86400                           ; RETRY
                            86400                           ; EXPIRE
                            1                               ; MINIMUM
                    )

    $TTL 86400

    @       NS      ns1.whoami6.domain.example.
    @       NS      ns2.whoami6.domain.example.
    @       NS      ns3.whoami6.domain.example.
    @       NS      ns4.whoami6.domain.example.

    ns1     AAAA    2001:db8:100::53
    ns2     AAAA    2001:db8:200::53
    ns3     AAAA    2001:db8:300::53
    ns4     AAAA    2001:db8:400::53

The parent domain would then delegate whoami.domain.example to
ns[1-4].whoami.domain.example and whoami6.domain.example to
ns[1-4].whoami6.domain.example, and include the corresponding A-only or
AAAA-only glue records.

.. NOTE::
   This module is not configurable.
