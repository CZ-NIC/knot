Introduction
============

The reader of this document is assumed to know the principles of
Domain Name System.

What is Knot DNS
----------------

Knot DNS is a high-performance open source DNS server. It
implements only authoritative domain name service. Knot DNS
is best suited for use on TLD domains but can reliably serve
any other zones as well.

Knot DNS benefits from its multi-threaded and mostly lock-free
implementation which allows it to scale well on SMP systems and
operate non-stop even when adding or removing zones.

Knot DNS features
-----------------

Knot DNS supports the following DNS features:

* IN class and partially CH class
* TCP/UDP protocols
* AXFR, IXFR - master, slave
* TSIG
* EDNS0
* DNSSEC, including NSEC3
* NSID
* Dynamic updates
* Response Rate Limiting
* RR types A, NS, CNAME, SOA, PTR, HINFO, MINFO, MX, TXT, RP, AFSDB, RT, KEY,
  AAAA, LOC, SRV, NAPTR, KX, CERT, DNAME, APL, DS, SSHFP, IPSECKEY, RRSIG, NSEC,
  DNSKEY, DHCID, NSEC3, NSEC3PARAM, TLSA, SPF, NID, L32, L64, LP, EUI48, EUI64
  and Unknown

Server features:

* Adding/removing zones on-the-fly
* Reconfiguring server instance on-the-fly
* IPv4 / IPv6 support
* Semantic checks of zones
* Persistent zone timers

For more info and downloads see `www.knot-dns.cz <https://www.knot-dns.cz>`_.

Git repository: `git://git.nic.cz/knot-dns.git <https://gitlab.labs.nic.cz/knot/knot-dns/tree/master>`_

Knot DNS issue tracker: `gitlab.labs.nic.cz/knot/knot-dns/issues <https://gitlab.labs.nic.cz/knot/knot-dns/issues>`_

Knot DNS users mailing list: `knot-dns-users@lists.nic.cz <mailto:knot-dns-users@lists.nic.cz>`_

Scope of this document
----------------------

This document covers the basic information on installing, configuring
and troubleshooting the Knot DNS server.

License
-------

Knot DNS is licensed under `GNU General Public License <https://www.gnu.org/copyleft/gpl.html>`_
version 3 or (at your option) any later version. The full text of the license
is available in the ``COPYING`` file distributed with the source codes.
