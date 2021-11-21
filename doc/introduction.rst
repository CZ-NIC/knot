.. highlight:: none
.. _Introduction:

************
Introduction
************

What is Knot DNS
================

Knot DNS is a high-performance open-source DNS server. It
implements only the authoritative domain name service. Knot DNS
can reliably serve TLD domains as well as any other zones.

Knot DNS benefits from its multi-threaded and mostly lock-free
implementation which allows it to scale well on SMP systems and
operate non-stop even when adding or removing zones.

The server itself is accompanied by several utilities for general DNS
operations or for maintaining the server.

For more info and downloads see `www.knot-dns.cz <https://www.knot-dns.cz>`_.

Knot DNS features
=================

DNS features:

* Primary and secondary server operation
* Internet class (IN)
* DNS extension (EDNS0, EDE)
* TCP and UDP protocols
* Zone catalog generation and interpretation
* Minimal responses
* Dynamic zone updates
* DNSSEC with NSEC and NSEC3
* ZONEMD generation and validation
* Transaction signature using TSIG
* Full and incremental zone transfers (AXFR, IXFR)
* Name server identification using NSID or Chaos TXT records
* Resource record types A, NS, CNAME, SOA, PTR, HINFO, MINFO, MX,
  TXT, RP, AFSDB, RT, KEY, AAAA, LOC, SRV, NAPTR, KX, CERT, DNAME, APL, DS,
  SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM, TLSA, SMIMEA,
  CDS, CDNSKEY, OPENPGPKEY, CSYNC, ZONEMD, SVCB, HTTPS, SPF, NID, L32, L64, LP,
  EUI48, EUI64, URI, CAA, and Unknown

Server features:

* IPv4 and IPv6 support
* Semantic zone checks
* Server control interface
* Zone journal storage
* Persistent zone event timers
* YAML-based or database-based configuration
* Query processing modules with dynamic loading
* On-the-fly zone management and server reconfiguration
* Multithreaded DNSSEC zone signing and zone validation
* Automatic DNSSEC key management
* Zone data backup and restore
* Offline KSK operation
* PKCS #11 interface

Remarkable module extensions:

* Response rate limiting
* Forward and reverse records synthesis
* DNS request traffic statistics
* Efficient DNS traffic logging interface
* Dnstap traffic logging
* Online DNSSEC signing
* GeoIP response tailoring supporting ECS and DNSSEC

Remarkable supported networking features:

* TCP Fast Open (client and server)
* High-performance UDP and TCP through AF_XDP processing (on Linux 4.18+)
* SO_REUSEPORT (on Linux) or SO_REUSEPORT_LB (on FreeBSD 12.0+) on UDP and by choice on TCP
* Binding to non-local addresses (IP_FREEBIND on Linux, IP_BINDANY/IPV6_BINDANY on FreeBSD)
* Ignoring PMTU information for IPv4/UDP via IP_PMTUDISC_OMIT

License
=======

Knot DNS is licensed under the `GNU General Public License <https://www.gnu.org/copyleft/gpl.html>`_
version 3 or (at your option) any later version. The full text of the license
is available in the ``COPYING`` file distributed with source code.
