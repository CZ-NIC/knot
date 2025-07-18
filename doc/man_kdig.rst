.. highlight:: none

``kdig`` – Advanced DNS lookup utility
======================================

Synopsis
--------

:program:`kdig` [*common-settings*] [*query* [*settings*]]...

:program:`kdig` **-h**

Description
-----------

This utility sends one or more DNS queries to a nameserver. Each query can have
individual *settings*, or it can be specified globally via *common-settings*,
which must precede *query* specification.

Parameters
..........

*query*
  *name* | **-q** *name* | **-x** *address* | **-G** *tapfile*

*common-settings*, *settings*
  [*query_class*] [*query_type*] [**@**\ *server*]... [*options*]

*name*
  Is a domain name that is to be looked up.

*server*
  Is a domain name or an IPv4 or IPv6 address of the nameserver to send a query
  to. An additional port can be specified using address:port ([address]:port
  for IPv6 address), address@port, or address#port notation. A value which begins
  with '/' character is considered an absolute UNIX socket path. If no server is
  specified, the servers from :file:`/etc/resolv.conf` are used.

If no arguments are provided, :program:`kdig` sends NS query for the root
zone.

Query classes
.............

A *query_class* can be either a DNS class name (IN, CH) or generic class
specification **CLASS**\ *XXXXX* where *XXXXX* is a corresponding decimal
class number. The default query class is IN.

Query types
...........

A *query_type* can be either a DNS resource record type
(A, AAAA, NS, SOA, DNSKEY, ANY, etc.) or one of the following:

**TYPE**\ *XXXXX*
  Generic query type specification where *XXXXX* is a corresponding decimal
  type number.

**AXFR**
  Full zone transfer request.

**IXFR=**\ *serial*
  Incremental zone transfer request for specified SOA serial number
  (i.e. all zone updates since the specified zone version are to be returned).

**NOTIFY=**\ *serial*
  Notify message with a SOA serial hint specified.

**NOTIFY**
  Notify message with a SOA serial hint unspecified.

The default query type is A.

Options
.......

**-4**
  Use the IPv4 protocol only.

**-6**
  Use the IPv6 protocol only.

**-b** *address*
  Set the source IP address of the query to *address*. The address must be a
  valid address for local interface or :: or 0.0.0.0. An optional port
  can be specified in the same format as the *server* value.

**-c** *class*
  An explicit *query_class* specification. See possible values above.

**-d**
  Enable debug messages.

**-dd**
  Enable more verbose debug messages (print Subject Alternative Name).

**-h**, **--help**
  Print the program help.

**-k** *keyfile*
  Use the TSIG key stored in a file *keyfile* to authenticate the request. The
  file must contain the key in the same format as accepted by the
  **-y** option.

**-p** *port*
  Set the nameserver port number or service name to send a query to. The default
  port is 53.

**-q** *name*
  Set the query name. An explicit variant of *name* specification. If no *name*
  is provided, empty question section is set.

**-t** *type*
  An explicit *query_type* specification. See possible values above.

**-V**, **--version**
  Print the program version. The option **-VV** makes the program
  print the compile time configuration summary.

**-x** *address*
  Send a reverse (PTR) query for IPv4 or IPv6 *address*. The correct name, class
  and type is set automatically.

**-y** [*alg*:]\ *name*:*key*
  Use the TSIG key named *name* to authenticate the request. The *alg*
  part specifies the algorithm (the default is hmac-sha256) and *key* specifies
  the shared secret encoded in Base64.

**-E** *tapfile*
  Export a dnstap trace of the query and response messages received to the
  file *tapfile*.

**-G** *tapfile*
  Generate message output from a previously saved dnstap file *tapfile*.

**+**\ [\ **no**\ ]\ **multiline**
  Wrap long records to more lines and improve human readability.

**+**\ [\ **no**\ ]\ **short**
  Show record data only.

**+**\ [\ **no**\ ]\ **generic**
  Use the generic representation format when printing resource record types
  and data.

**+**\ [\ **no**\ ]\ **crypto**
  Display the DNSSEC keys and signatures values in base64, instead of omitting them.
  (*)

**+**\ [\ **no**\ ]\ **aaflag**
  Set the AA flag.

**+**\ [\ **no**\ ]\ **tcflag**
  Set the TC flag.

**+**\ [\ **no**\ ]\ **rdflag**
  Set the RD flag. (*)

**+**\ [\ **no**\ ]\ **recurse**
  Same as **+**\ [\ **no**\ ]\ **rdflag**

**+**\ [\ **no**\ ]\ **raflag**
  Set the RA flag.

**+**\ [\ **no**\ ]\ **zflag**
  Set the zero flag bit.

**+**\ [\ **no**\ ]\ **adflag**
  Set the AD flag. (*)

**+**\ [\ **no**\ ]\ **cdflag**
  Set the CD flag.

**+**\ [\ **no**\ ]\ **doflag**
  Set the DO flag.

**+**\ [\ **no**\ ]\ **dnssec**
  Same as **+**\ [\ **no**\ ]\ **doflag**

**+**\ [\ **no**\ ]\ **all**
  Show all packet sections.

**+**\ [\ **no**\ ]\ **qr**
  Show the query packet.

**+**\ [\ **no**\ ]\ **header**
  Show the packet header. (*)

**+**\ [\ **no**\ ]\ **comments**
  Show commented section names. (*)

**+**\ [\ **no**\ ]\ **opt**
  Show the EDNS pseudosection. (*)

**+**\ [\ **no**\ ]\ **opttext**
  Try to show unknown EDNS options as text.

**+**\ [\ **no**\ ]\ **optpresent**
  Show EDNS in presentation format according to the specification in version
  `draft-peltan-edns-presentation-format-01 <https://www.ietf.org/archive/id/draft-peltan-edns-presentation-format-01.html>`_.

**+**\ [\ **no**\ ]\ **question**
  Show the question section. (*)

**+**\ [\ **no**\ ]\ **answer**
  Show the answer section. (*)

**+**\ [\ **no**\ ]\ **authority**
  Show the authority section. (*)

**+**\ [\ **no**\ ]\ **additional**
  Show the additional section. (*)

**+**\ [\ **no**\ ]\ **tsig**
  Show the TSIG pseudosection. (*)

**+**\ [\ **no**\ ]\ **stats**
  Show trailing packet statistics. (*)

**+**\ [\ **no**\ ]\ **class**
  Show the DNS class. (*)

**+**\ [\ **no**\ ]\ **ttl**
  Show the TTL value. (*)

**+**\ [\ **no**\ ]\ **tcp**
  Use the TCP protocol (default is UDP for standard query and TCP for AXFR/IXFR).

**+**\ [\ **no**\ ]\ **fastopen**
  Use TCP Fast Open.

**+**\ [\ **no**\ ]\ **ignore**
  Don't use TCP automatically if a truncated reply is received.

**+**\ [\ **no**\ ]\ **keepopen**
  Keep TCP connection open for the following query if it has the same connection
  configuration. This applies to +tcp, +tls, and +https operations. The connection
  is considered in the context of a single kdig call only.

**+**\ [\ **no**\ ]\ **tls**
  Use TLS with the Opportunistic privacy profile (:rfc:`7858#section-4.1`).

**+**\ [\ **no**\ ]\ **tls-ca**\[\ =\ *FILE*\]
  Use TLS with a certificate validation. Certification authority certificates
  are loaded from the specified PEM file (default is system certificate storage
  if no argument is provided).
  Can be specified multiple times. If the +tls-hostname option is not provided,
  the name of the target server (if specified) is used for strict authentication.

**+**\ [\ **no**\ ]\ **tls-pin**\ =\ *BASE64*
  Use TLS with the Out-of-Band key-pinned privacy profile (:rfc:`7858#section-4.2`).
  The PIN must be a Base64 encoded SHA-256 hash of the X.509 SubjectPublicKeyInfo.
  Can be specified multiple times.

**+**\ [\ **no**\ ]\ **tls-hostname**\ =\ *STR*
  Use TLS with a remote server hostname check.

**+**\ [\ **no**\ ]\ **tls-sni**\ =\ *STR*
  Use TLS with a Server Name Indication.

**+**\ [\ **no**\ ]\ **tls-keyfile**\ =\ *FILE*
  Use TLS with a client keyfile.

**+**\ [\ **no**\ ]\ **tls-certfile**\ =\ *FILE*
  Use TLS with a client certfile.

**+**\ [\ **no**\ ]\ **tls-ocsp-stapling**\[\ =\ *H*\]
  Use TLS with a valid stapled OCSP response for the server certificate
  (%u or specify hours). OCSP responses older than the specified period are
  considered invalid.

**+**\ [\ **no**\ ]\ **https**\[\ =\ *URL*\]
  Use HTTPS (DNS-over-HTTPS) in wire format (:rfc:`1035#section-4.2.1`).
  It is also possible to specify URL=\[authority\]\[/path\] where request
  will be sent to. Any leading scheme and authority indicator (i.e. //) are ignored.
  Authority might also be specified as the *server* (using the parameter `@`).
  If *path* is specified and *authority* is missing, then the *server*
  is used as authority together with the specified *path*.
  Library *libnghttp2* is required.

**+**\ [\ **no**\ ]\ **https-get**
  Use HTTPS with HTTP/GET method instead of the default HTTP/POST method.
  Library *libnghttp2* is required.

**+**\ [\ **no**\ ]\ **quic**
  Use QUIC (DNS-over-QUIC).

**+**\ [\ **no**\ ]\ **nsid**
  Request the nameserver identifier (NSID).

**+**\ [\ **no**\ ]\ **zoneversion**
  Request the EDNS zone version.

**+**\ [\ **no**\ ]\ **bufsize**\ =\ *B*
  Set EDNS buffer size in bytes (default is 1232 bytes).

**+**\ [\ **no**\ ]\ **padding**\[\ =\ *B*\]
  Use EDNS(0) padding option to pad queries, optionally to a specific
  size. The default is to pad queries with a sensible amount when using
  +tls, and not to pad at all when queries are sent without TLS.  With
  no argument (i.e., just +padding) pad every query with a sensible
  amount regardless of the use of TLS. With +nopadding, never pad.

**+**\ [\ **no**\ ]\ **alignment**\[\ =\ *B*\]
  Align the query to B\-byte-block message using the EDNS(0) padding option
  (default is no or 128 if no argument is specified).

**+**\ [\ **no**\ ]\ **subnet**\ =\ *SUBN*
  Set EDNS(0) client subnet SUBN=addr/prefix.

**+**\ [\ **no**\ ]\ **edns**\[\ =\ *N*\]
  Use EDNS version (default is 0).

**+**\ [\ **no**\ ]\ **msgdelay**\ =\ *T*
  Wait the specified number of milliseconds before receiving each AXFR/IXFR message.

**+**\ [\ **no**\ ]\ **timeout**\ =\ *T*
  Set the wait-for-reply interval in seconds (default is 5 seconds). This timeout
  applies to each query attempt. Zero value or *notimeout* is interpreted as
  infinity.

**+**\ [\ **no**\ ]\ **retry**\ =\ *N*
  Set the number (>=0) of UDP retries (default is 2). This doesn't apply to
  AXFR/IXFR.

**+**\ [\ **no**\ ]\ **expire**
  Sets the EXPIRE EDNS option.

**+**\ [\ **no**\ ]\ **cookie**\[\ =\ *HEX*\]
  Attach EDNS(0) cookie to the query.

**+**\ [\ **no**\ ]\ **badcookie**
  Repeat a query with the correct cookie.

**+**\ [\ **no**\ ]\ **ednsopt**\[\ =\ *CODE*\[:*HEX*\]\]
  Send custom EDNS option. The *CODE* is EDNS option code in decimal, *HEX*
  is an optional hex encoded string to use as EDNS option value. This argument
  can be used multiple times. +noednsopt clears all EDNS options specified by
  +ednsopt.

**+**\ [\ **no**\ ]\ **proxy**\ =\ *SRC_ADDR*\[#\ *SRC_PORT*\]-*DST_ADDR*\[#\ *DST_PORT*\]
  Add PROXYv2 header with the specified source and destination addresses to the query.
  The default source port is 0 and destination port 53.

**+**\ [\ **no**\ ]\ **json**
  Use JSON for output encoding (RFC 8427).

**+noidn**
  Disable the IDN transformation to ASCII and vice versa. IDN support depends
  on libidn2 availability during project building! If used in *common-settings*,
  all IDN transformations are disabled. If used in the individual query *settings*,
  transformation from ASCII is disabled on output for the particular query. Note
  that IDN transformation does not preserve domain name letter case.

Notes
-----

By default, only options marked with (*) are enabled.

Options **-k** and **-y** can not be used simultaneously.

Dnssec-keygen keyfile format is not supported. Use :manpage:`keymgr(8)` instead.

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

Examples
--------

1. Get A records for example.com::

     $ kdig example.com A

2. Perform AXFR for zone example.com from the server 192.0.2.1::

     $ kdig example.com -t AXFR @192.0.2.1

3. Get A records for example.com from 192.0.2.1 and reverse lookup for address
   2001:DB8::1 from 192.0.2.2. Both using the TCP protocol::

     $ kdig +tcp example.com -t A @192.0.2.1 -x 2001:DB8::1 @192.0.2.2

4. Get SOA record for example.com, use TLS, use system certificates, check
   for specified hostname, check for certificate pin, and print additional
   debug info::

     $ kdig -d @185.49.141.38 +tls-ca +tls-host=getdnsapi.net \
       +tls-pin=foxZRnIh9gZpWnl+zEiKa0EJ2rdCGroMWm02gaxSc9S= soa example.com

5. DNS over HTTPS examples (various DoH implementations)::

     $ kdig @1.1.1.1 +https example.com.
     $ kdig @193.17.47.1 +https=/doh example.com.
     $ kdig @8.8.4.4 +https +https-get example.com.
     $ kdig @8.8.8.8 +https +tls-hostname=dns.google +fastopen example.com.

6. More queries share one DoT connection::

     $ kdig @1.1.1.1 +tls +keepopen abc.example.com A mail.example.com AAAA

7. Query the name server identifier and version according to :rfc:`4892`::

     $ kdig @a.iana-servers.net. CH TXT id.server version.server

Files
-----

:file:`/etc/resolv.conf`

See Also
--------

:manpage:`khost(1)`, :manpage:`knsupdate(1)`, :manpage:`keymgr(8)`.
