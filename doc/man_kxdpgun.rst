.. highlight:: console

kxdpgun – DNS benchmarking tool
===============================

Synopsis
--------

:program:`kxdpgun` [*options*] **-i** *filename* *targetIP*

Description
-----------

Powerful generator of DNS traffic, sending and receiving packets through XDP.

Queries are generated according to a textual file which is read sequentially
in a loop until a configured duration elapses. The order of queries is not
guaranteed. Responses are received (unless disabled) and counted, but not
checked against queries.

The number of parallel threads is autodetected according to the number of queues
configured for the network interface.

Options
.......

**-t**, **--duration** *seconds*
  Duration of traffic generation, specified as a decimal number in seconds
  (default is 5.0).

**-T**, **--tcp**\[\ **=**\ *debug_mode*\]
  Send queries over TCP. See the list of optional debug modes below.

**-U**, **--quic**\[\ **=**\ *debug_mode*\]
  Send queries over QUIC. See the list of optional debug modes below.

**-Q**, **--qps** *queries*
  Number of queries-per-second (approximately) to be sent (default is 1000).
  The program is not optimized for low speeds at which it may lose
  communication packets. The recommended minimum speed is 2 packets per thread
  (Rx/Tx queue).

**-b**, **--batch** *size*
  Send more queries in a batch. Improves QPS but may affect the counterpart's
  packet loss (default is 10 for UDP and 1 for TCP).

**-r**, **--drop**
  Drop incoming responses. Improves QPS, but disables response statistics.

**-p**, **--port** *number*
  Remote destination port (default is 53).

**-F**, **--affinity** *cpu_spec*
  CPU affinity for all threads specified in the format [<cpu_start>][s<cpu_step>],
  where <cpu_start> is the CPU ID for the first thread and <cpu_step> is the
  CPU ID increment for next thread (default is 0s1).

**-i**, **--infile** *filename*
  Path to a file with query templates.

**-I**, **--interface** *interface*
  Network interface for outgoing communication. This can be useful in situations
  when the interfaces are in a bond for example.

**-l**, **--local** *localIP*\ [**/**\ *prefix*]
  Override the auto-detected source IP address. If an address range is specified
  instead, various IPs from the range will be used for different queries uniformly.

*targetIP*
  The IPv4 or IPv6 address of remote destination.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

Queries file format
...................

Each line describes a query in the form:

*query_name* *query_type* [*flags*]

Where *query_name* is a domain name to be queried, *query_type* is a record type
name, and *flags* is a single character:

**E** Send query with EDNS.

**D** Request DNSSEC (EDNS + DO flag).

TCP debug modes
...............

**1**
  Just send SYN and receive SYN-ACK.

**2**
  Perform TCP handshake and don't send anything, allow close initiated by counterpart.

**3**
  Perform TCP handshake and don't react further.

**5**
  Send incomplete query (N-1 bytes) and don't react further.

**7**
  Send query and don't ACK the response or anything further.

**8**
  Don't close the connection and ignore close by counterpart.

**9**
  Operate normally except for not ACKing the final FIN+ACK.

Signals
.......

Sending USR1 signal to a running process triggers current statistics dump
to the standard output.

Notes
-----

Linux kernel 4.18+ is required.

The utility has to be executed under root or with these capabilities:
CAP_NET_RAW, CAP_NET_ADMIN, CAP_SYS_ADMIN, and CAP_SYS_RESOURCE if maximum
locked memory limit is too low on Linux < 5.11.

The utility allocates source UDP/TCP ports from the range 2000-65535.

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

Examples
--------

Manually created queries file::

  abc6.example.com. AAAA
  nxdomain.example.com. A
  notzone. A
  a.example.com. NS E
  ab.example.com. A D
  abcd.example.com. DS D

Queries file generated from a zone file (Knot DNS format)::

  cat ZONE_FILE | awk "{print \$1,\$3}" | grep -E "(NS|DS|A|AAAA|PTR|MX|SOA)$" | sort -u -R > queries.txt

Basic usage::

  # kxdpgun -i ~/queries.txt 2001:DB8::1

*Using UDP with increased batch size*::

  # kxdpgun -t 20 -Q 1000000 -i ~/queries.txt -b 20 -p 8853 192.0.2.1

*Using TCP*::

  # kxdpgun -t 20 -Q 100000 -i ~/queries.txt -T -p 8853 192.0.2.1

See Also
--------

:manpage:`kdig(1)`.
