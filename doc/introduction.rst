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

For more info and downloads see `www.knot-dns.cz <https://www.knot-dns.cz>`_.

Knot DNS features
=================

DNS features:

* Master and slave operation
* Internet class (IN)
* DNS extension (EDNS0)
* TCP and UDP protocols
* Dynamic zone updates
* DNSSEC with NSEC and NSEC3
* Transaction signature using TSIG
* Full and incremental zone transfers (AXFR, IXFR)
* Name server identification using NSID or Chaos TXT records
* Resource record types A, NS, CNAME, SOA, PTR, HINFO, MINFO, MX,
  TXT, RP, AFSDB, RT, KEY, AAAA, LOC, SRV, NAPTR, KX, CERT, DNAME, APL, DS,
  SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM, TLSA, CDS,
  CDNSKEY, SPF, NID, L32, L64, LP, EUI48, EUI64, URI, CAA, and Unknown

Server features:

* IPv4 and IPv6 support
* Semantic zone checks
* Server control interface
* Zone journal storage
* Persistent zone event timers
* YAML-based or database-based configuration
* Query processing modules with dynamic loading
* On-the-fly zone management and server reconfiguration
* Automatic DNSSEC signing with automatic key maganement and PKCS #11 interface

Remarkable module extensions:

* Response rate limiting
* Forward and reverse records synthesis
* DNS request traffic statistics
* Dnstap traffic logging
* Online DNSSEC signing
* GeoIP response tailoring supporting ECS and DNSSEC 

License
=======

Knot DNS is licensed under the `GNU General Public License <https://www.gnu.org/copyleft/gpl.html>`_
version 3 or (at your option) any later version. The full text of the license
is available in the ``COPYING`` file distributed with source code.
