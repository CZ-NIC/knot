.. highlight:: none
.. _Introduction:

************
Introduction
************

What is Knot DNS
================

Knot DNS is a high-performance open-source DNS server. It
implements only the authoritative domain name service. Knot DNS
is best suited for use on TLD domains but it can reliably serve
any other zones as well.

Knot DNS benefits from its multi-threaded and mostly lock-free
implementation which allows it to scale well on SMP systems and
operate non-stop even when adding or removing zones.

Knot DNS features
=================

DNS features:

* IN class and partially CH class
* TCP/UDP protocols
* AXFR, IXFR – master, slave
* TSIG
* EDNS0
* DNSSEC, including NSEC3
* NSID
* Dynamic updates
* Response Rate Limiting
* RR types A, NS, CNAME, SOA, PTR, HINFO, MINFO, MX, TXT, RP, AFSDB, RT, KEY,
  AAAA, LOC, SRV, NAPTR, KX, CERT, DNAME, APL, DS, SSHFP, IPSECKEY, RRSIG, NSEC,
  DNSKEY, DHCID, NSEC3, NSEC3PARAM, TLSA, CDS, CDNSKEY, SPF, NID, L32, L64, LP,
  EUI48, EUI64, URI, CAA and Unknown

Server features:

* Adding/removing zones on-the-fly
* Reconfiguring server instance on-the-fly
* Dynamic configuration
* IPv4 and IPv6 support
* Semantic checks of zones
* DDNS support
* Persistent zone timers
* Automatic DNSSEC signing
* PKCS #11 interface
* Forward and reverse records synthesis

For more info and downloads see `www.knot-dns.cz <https://www.knot-dns.cz>`_.

Git repository: `git://git.nic.cz/knot-dns.git <https://gitlab.labs.nic.cz/labs/knot/tree/master>`_

Knot DNS issue tracker: `gitlab.labs.nic.cz/labs/knot/issues <https://gitlab.labs.nic.cz/labs/knot/issues>`_

Knot DNS users mailing list: `knot-dns-users@lists.nic.cz <mailto:knot-dns-users@lists.nic.cz>`_

License
=======

Knot DNS is licensed under the `GNU General Public License <https://www.gnu.org/copyleft/gpl.html>`_
version 3 or (at your option) any later version. The full text of the license
is available in the ``COPYING`` file distributed with source code.
