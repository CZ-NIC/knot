/*!

\mainpage Knot DNS API Documentation

\par Knot DNS homepage
  https://www.knot-dns.cz

\par Git repository
  https://gitlab.nic.cz/knot/knot-dns

\par Modules
- \subpage libknot-page
- \subpage libdnssec-page
- \subpage libzscanner-page
- \subpage knotd-page

\copyright Licensed under the terms of
 [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.txt)
 version 3 or later.


\page libknot-page libknot - General DNS library

\section libknot-content Sections
 - \ref ctl       — Server control interface
 - \ref db        — Database abstraction
 - \ref dname     — Domain name manipulation
 - \ref pkt       — DNS packet manipulation
 - \ref probe     — DNS traffic probe interface
 - \ref rr        — DNS resource record manipulation
 - \ref rrtype    — DNS resource record types
 - \ref knot-tsig — TSIG operations
 - \ref wire      — Packet wire data manipulation
 - \ref xdp       — XDP interface
 - \ref yparser   — Simple YAML parser

\defgroup ctl        ctl
\defgroup db         db
\defgroup dname      dname
\defgroup pkt        pkt
\defgroup probe      probe
\defgroup rr         rr
\defgroup rrtype     rrtype
\defgroup knot-tsig  tsig
\defgroup wire       wire
\defgroup xdp        xdp
\defgroup yparser    yparser


\page libdnssec-page libdnssec - DNSSEC library

\section libdnssec-content Sections
 - \ref binary   — Universal binary data container
 - \ref crypto   — Cryptographic backend
 - \ref digest   — Data hashing operations
 - \ref error    — Error codes and error reporting
 - \ref key      — DNSSEC key manipulation
 - \ref keyid    — DNSSEC key ID manipulation
 - \ref keystore — DNSSEC private key store
 - \ref keytag   — DNSSEC key tag computation
 - \ref nsec     — NSEC and NSEC3 operations
 - \ref pem      — PEM key format operations
 - \ref random   — Pseudo-random number generation
 - \ref sign     — DNSSEC signing and verification
 - \ref tsig     — TSIG signing

\defgroup binary   binary
\defgroup crypto   crypto
\defgroup digest   digest
\defgroup error    error
\defgroup key      key
\defgroup keyid    keyid
\defgroup keystore keystore
\defgroup keytag   keytag
\defgroup nsec     nsec
\defgroup pem      pem
\defgroup random   random
\defgroup sign     sign
\defgroup tsig     tsig


\page libzscanner-page libzscanner - DNS zone file parser

\section libzscanner-content Sections
 - \ref zscanner — DNS zone file parser

\defgroup zscanner zscanner


\page knotd-page knotd - Knot DNS module interface

\section knotd-content Sections
 - \ref module — Knot DNS module interface

\defgroup module module

*/
