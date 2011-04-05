/*!

\defgroup server            Server control module.
\defgroup threading         Threading API.
\defgroup network           Socket API.
\defgroup query_processing  DNS query processing.
\defgroup utils             Utilities, constants and macros.
\defgroup debugging         Server debugging API.
\defgroup logging           Server logging API.
\defgroup statistics        Statistics module (optional).
\defgroup dnslib            dnslib - Generic DNS library.
\defgroup hashing           Hash table and functions.
\defgroup common_lib        Common library.
\defgroup alloc             Memory allocation.
\defgroup tests             Unit tests.
\defgroup zoneparser        Zone compiler utility
\defgroup ctl               Control utility

\mainpage Knot API documentation.

Knot is an open-source, high-performace, purely authoritative DNS server.

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
$ bin/knot-zoneparser -o example.com.db example.com. samples/example.com.zone
$ bin/knot-zoneparser -o other-zone.db other-zone.com. other-zone.com.zone
\endcode

2. Run the server with the compiled zones (use -d to run as a daemon)
\code
$ bin/knot example.com.db other-zone.db
\endcode

<h3>Using knotc</h3>
- This approach currently supports only one zone file.
- Compiled zone is stored in user's home directory.

1. Add path to knot and knot-zoneparser executables to PATH

2. Compile zone
\code
$ bin/knotc compile example.com. samples/example.com.zone
\endcode

3. Run the server
\code
$ bin/knotc start
\endcode

<h2>Server modules</h2>
- \ref server
- \ref threading
- \ref network
- \ref query_processing
- \ref utils
- \ref debugging
- \ref logging
- \ref statistics

<h2>DNS library</h2>

- \ref dnslib
- \ref hashing

<h2>Common library</h2>

- \ref common_lib
- \ref alloc

<h2>Other modules</h2>
- \ref tests
- \ref zoneparser
- \ref ctl
 */
