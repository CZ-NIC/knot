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
- automake
- autoconf
- libtool

<h2>Installation</h2>
Knot uses autotools to generate makefiles.

\todo Add some more info about usage and requirements.

\code
$ autoreconf -i
$ ./configure
$ make
\endcode

<h2>Starting the server</h2>

When compiled, the following executables are created (in the src/ directory):
- \em knotd              - The server
- \em knotc              - Control utility
- \em knot-zcompile      - Zone compiler
- \em unittests          - Unit tests for the server and dnslib
- \em unittests-zcompile - Unit tests for the zone compiler

1. Add path to knotd and knot-zcompile executables to PATH

2. Prepare a configuration file. You may copy and edit the one provided with
   the server (\em samples/knot.conf.sample).

2. Compile zone
\code
$ src/knotc -c path-to-config-file compile
\endcode

3. Run the server
\code
$ src/knotc -c path-to-config-file start
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
