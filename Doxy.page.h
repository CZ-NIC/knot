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
\defgroup zoneparser        Zone parser utility
\defgroup ctl               Control utility

\mainpage CuteDNS API documentation.

CuteDNS is an open-source, high-performace, purely authoritative DNS server.

<h2>Requirements</h2>
- liburcu (at least 0.4.5): http://lttng.org/urcu

<h2>Installation</h2>
- Compile the server (and all utilities).
\code
$ make
\endcode

<h2>Starting the server</h2>

<h3>Manual approach</h3>

1. Compile zones
\code
$ bin/zoneparser -o example.com.db example.com. samples/example.com.zone
$ bin/zoneparser -o other-zone.db other-zone.com. other-zone.com.zone
\endcode

2. Run the server with the compiled zones (use -d to run as a daemon)
\code
$ bin/cutedns example.com.db other-zone.db
\endcode

<h3>Using cutectl</h3>
- This approach currently supports only one zone file.
- Compiled zone is stored in user's home directory.

1. Add path to cutedns and zonecompiler executables to PATH

2. Compile zone
\code
$ bin/cutectl compile example.com. samples/example.com.zone
\endcode

3. Run the server
\code
$ bin/cutectl start
\endcode

<h2>Server modules</h2>
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

<h2>Other modules</h2>
- \ref tests
- \ref zoneparser
- \ref ctl
 */
