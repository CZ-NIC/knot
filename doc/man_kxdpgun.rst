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

The number of parallel threads is autodected according to the number of queues
configured for the network interface.

Options
.......

**-t**, **--duration** *seconds*
  Duration of traffic generation, specified as a decimal number in seconds
  (default is 5.0).

**-Q**, **--qps** *queries*
  Number of queries-per-second (approximately) to be sent (default is 1000).

**-b**, **--batch** *size*
  Send more queries in a batch. Improves QPS but may affect the counterpart's
  packet loss (default is 10).

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

Notes
-----

Linux kernel 4.18+ is required.

The utility has to be executed under root or with these capabilities:
CAP_NET_RAW, CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_SYS_RESOURCE, CAP_SETPCAP.

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

Program usage::

  # kxdpgun -i ~/queries.txt 2001:1489:fffe:10::16

::

  # kxdpgun -t 120 -Q 6000000 -i ~/queries.txt -b 5 -r -p 8853 192.168.101.2

See Also
--------

:manpage:`kdig(1)`.
