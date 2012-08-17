/*!

\defgroup server            Server control module.
\defgroup threading         Threading API.
\defgroup network           Socket API.
\defgroup config            Server configuration.
\defgroup query_processing  DNS query processing.
\defgroup utils             Utilities, constants and macros.
\defgroup debugging         Server debugging API.
\defgroup logging           Server logging API.
\defgroup statistics        Statistics module (optional).
\defgroup libknot           libknot - library of DNS-related functions
\defgroup hashing           Hash table and functions.
\defgroup common_lib        Common library.
\defgroup alloc             Memory allocation.
\defgroup tests             Unit tests.
\defgroup zoneparser        Zone compiler utility
\defgroup ctl               Control utility
\defgroup zone-load-dump    Zone loading and dumping
\defgroup xfr               Zone transfers

\mainpage Knot API documentation.

Knot is an open-source, high-performace, purely authoritative DNS server.

<h2>Features</h2>

Knot DNS supports the following DNS features:
- TCP/UDP protocols
- AXFR - master, slave
- IXFR - master (primary master experimental), slave
- TSIG
- ENDS0
- DNSSEC, including NSEC3
- NSID
- Unknown RR types

Server features:
- Adding/removing zones on-the-fly
- Reconfiguring server instance on-the-fly
- IPv4 / IPv6 support
- Semantic checks of zones

<h2>Compiling and running the server</h2>

See the User manual - links to current version are provided in the
<a href="https://git.nic.cz/redmine/projects/knot-dns/wiki">Knot DNS Wiki</a>.

Alternatively you can generate the manual from the sources in Info format:
\code
$ make doc
\endcode

or in PDF:

\code
$ make pdf
\endcode

<h2>Server modules</h2>
- \ref server
- \ref threading
- \ref network
- \ref config
- \ref query_processing
- \ref utils
- \ref debugging
- \ref logging
- \ref statistics

<h2>DNS library</h2>
- \ref libknot
- \ref hashing
- \ref xfr

<h2>Zone processing</h2>
- \ref zoneparser
- \ref zone-load-dump

<h2>Common library</h2>
- \ref common_lib
- \ref alloc

<h2>Other modules</h2>
- \ref tests
- \ref ctl
 */
