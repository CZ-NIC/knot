/*!

\defgroup server            Server control module.
\defgroup threading         Threading API.
\defgroup network           Socket API.
\defgroup query_processing  DNS query processing.
\defgroup dnslib            dnslib - Generic DNS library.
\defgroup hashing           Hash table and functions.
\defgroup data_structures   Other data structures.
\defgroup utils             Utilities, constants and macros.
\defgroup alloc             Memory allocation.
\defgroup statistics        Statistics module (optional).
\defgroup debugging         Project debugging API.
\defgroup logging           Logging API.
\defgroup tests             Unit tests.

\mainpage CuteDNS API documentation.

CuteDNS is an open-source, high-performace, purely authoritative DNS server.

<h2>Requirements</h2>
- ldns (at least 1.6.4): http://www.nlnetlabs.nl/projects/ldns/
- liburcu (at least 0.4.5): http://lttng.org/urcu

<h2>Installation</h2>
- Compile the server.
\code
make
\endcode

- Parse and pre-process zones (output is stored in ***.dump file, where *** is
  the file name of the original zone file).
\code
bin/zoneparser example.com. samples/example.com.zone
\endcode

- Run the server.
\code
bin/cutedns samples/example.com.zone.dump
\endcode

<h2>API modules</h2>
- \ref server
- \ref threading
- \ref network
- \ref query_processing
- \ref dnslib
- \ref hashing
- \ref data_structures
- \ref utils
- \ref alloc
- \ref statistics
- \ref debugging
- \ref logging
- \ref tests

 */
