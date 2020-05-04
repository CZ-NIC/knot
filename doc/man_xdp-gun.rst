.. highlight:: console

xdp-gun – DNS benchmarking tool
===============================

Synopsis
--------

:program:`xdp-gun` *options* *targetIP*

Description
-----------

Powerful generator of DNS traffic, sending and receving packets thru XDP.

Queries are generated according to a text file, read in a loop. Responses
are received (unless disabled) and counted, but not checked against queries.

The number of parallel threads is autodected according to number of queues
configured for the nework iface.

Options
.......

**-t** *duration*
  Duration of traffic generation, specified as a decimal number in seconds.
  *Default:* 5.0

**-Q** *qps*
  Number of queries-per-second (approximately) to be sent.
  *Default:* 1000

**-i** *queries_file*
  Path to a file with queries templates.
  *This parameter is obligatory.*

**-b** *batch_size*
  Send more queries in a batch. Improves QPS, but may affect the counterpart's packet loss.
  *Default:* 10

**-r**
  Drop incoming responses. Improves QPS, but disables response statistics.

**-p** *port*
  Remote destination port.
  *Default:* 53

*targetIP*
  The IPv4 or IPv6 address of remote destination.
  *This parameter is obligatory.*

Queries file format
...................

A text file, each line is a query format:

*query.name* *RRtype* [*flags*]

Where *query.name* is the DNS name to be queried, *RRtype* is the record type, and flags is
a string that may contain following characters:

**E** Send query with EDNS.

**D** Request DNSSEC.

The text file is read sequentially and when finished, started over from beginning. The only
exit condition is the configured duration. The order of queries is not guaranteed.

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
  abcd.example.com. DS ED

xdp-gun examples::

  # xdp-gun -i ~/queries.txt 2001:1489:fffe:10::16

::

  # xdp-gun -t 120 -Q 6000000 -i ~/queries.txt -b 5 -r -p 8853 192.168.101.2

See Also
--------

:manpage:`knotc(8)`, :manpage:`knotd(8)`.
