.. highlight:: console

khost – Simple DNS lookup utility
=================================

Synopsis
--------

:program:`khost` [*options*] *name* [*server*]

Description
-----------

This utility sends a DNS query for the *name* to the *server* and prints a reply
in more user-readable form. For more advanced DNS queries use :program:`kdig`
instead.

Parameters
..........

*name*
  Is a domain name that is to be looked up. If the *name* is IPv4 or IPv6
  address the PTR query type is used.

*server*
  Is a name or an address of the nameserver to send a query to.  The address
  can be specified using [address]:port notation. If no server is specified,
  the servers from :file:`/etc/resolv.conf` are used.

If no arguments are provided, :program:`khost` prints a short help.

Options
.......

**-4**
  Use the IPv4 protocol only.

**-6**
  Use the IPv6 protocol only.

**-a**
  Send ANY query with verbose mode.

**-d**
  Enable debug messages.

**-h**, **--help**
  Print the program help.

**-r**
  Disable recursion.

**-T**
  Use the TCP protocol.

**-v**
  Enable verbose output.

**-V**, **--version**
  Print the program version.

**-w**
  Wait forever for the reply.

**-c** *class*
  Set the query class (e.g. CH, CLASS4). The default class is IN.

**-t** *type*
  Set the query type (e.g. NS, IXFR=12345, TYPE65535). The default is to send 3
  queries (A, AAAA and MX).

**-R** *retries*
  The number (>=0) of UDP retries to query a nameserver. The default is 1.

**-W** *wait*
  The time to wait for a reply in seconds. This timeout applies to each query
  try. The default is 2 seconds.

Examples
--------

1. Get the A, AAAA and MX records for example.com::

     $ khost example.com

2. Get the reverse record for address 192.0.2.1::

     $ khost 192.0.2.1

3. Perform a verbose zone transfer for zone example.com::

     $ khost -t AXFR -v example.com

Files
-----

:file:`/etc/resolv.conf`

See Also
--------

:manpage:`kdig(1)`, :manpage:`knsupdate(1)`.
