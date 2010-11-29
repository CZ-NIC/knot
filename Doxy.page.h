/*!

\defgroup data_structures   Data structures.
\defgroup debugging         Project debugging API.
\defgroup hashing           Hashing functions.
\defgroup logging           Logging API.
\defgroup server            Server API.
\defgroup network           Networking.
\defgroup query_processing  DNS query processing.
\defgroup zonedb            Zone database.
\defgroup statistics        Statistics module (optional).
\defgroup utils             Utilities, constants and macros.
\defgroup tests             Unit tests.


\mainpage CuteDNS API documentation.

CuteDNS is an open-source, high-performace, purely authoritative DNS server.
- Multi-threaded architecture
- Supports all important DNS protocols
  - Full and incremental zone transfers
  - Dynamic zone updates
  - EDNS0 and DNSSEC compliant (including NSEC3)

<h2>Requirements</h2>
- ldns (at least 1.6.4): http://www.nlnetlabs.nl/projects/ldns/
- liburcu (at least 0.4.5): http://lttng.org/urcu

<h2>Installation</h2>

\code
make
bin/cutedns samples/example.com.zone
\endcode

<h2>API modules</h2>
- \ref data_structures
- \ref debugging
- \ref hashing
- \ref logging
- \ref server
- \ref network
- \ref query_processing
- \ref zonedb
- \ref statistics
- \ref utils
- \ref tests

 */
