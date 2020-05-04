.. highlight:: console

xdp-gun – DNS benchmarking tool
===============================

Synopsis
--------

:program:`xdp-gun` [*options*] **-i** *filename* *targetIP*

Description
-----------

Powerful generator of DNS traffic, sending and receving packets through XDP.

Queries are generated according to a textual file which is read sequentially
in a loop until a configured duration elapses. The order of queries is not
guaranteed. Responses are received (unless disabled) and counted, but not
checked against queries.

The number of parallel threads is autodected according to the number of queues
configured for the nework interface.

Options
.......

**-t**, **duration** *seconds*
  Duration of traffic generation, specified as a decimal number in seconds
  (default is 5.0).

**-Q**, **qps** *queries*
  Number of queries-per-second (approximately) to be sent (default is 1000).

**-b**, **batch** *size*
  Send more queries in a batch. Improves QPS but may affect the counterpart's
  packet loss (default is 10).

**-r**, **drop**
  Drop incoming responses. Improves QPS, but disables response statistics.

**-p** *port* *number*
  Remote destination port (default is 53).

**-i**, **infile** *filename*
  Path to a file with query templates.

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

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

Examples
--------

Queries file example::

  abc6.example.com. AAAA
  nxdomain.example.com. A
  notzone. A
  a.example.com. NS E
  ab.example.com. A D
  abcd.example.com. DS D

xdp-gun examples::

  # xdp-gun -i ~/queries.txt 2001:1489:fffe:10::16

::

  # xdp-gun -t 120 -Q 6000000 -i ~/queries.txt -b 5 -r -p 8853 192.168.101.2

See Also
--------

:manpage:`kdig(1)`.
