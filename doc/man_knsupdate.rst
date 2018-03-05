.. highlight:: console

knsupdate – Dynamic DNS update utility
======================================

.. _knsupdate_synopsis:

Synopsis
--------

:program:`knsupdate` [*options*] [*filename*]

.. _knsupdate_description:

Description
-----------

This utility sends Dynamic DNS update messages to a DNS server. Update content
is read from a file (if the parameter *filename* is given) or from the standard
input.

The format of updates is textual and is made up of commands. Every command is
placed on the separate line of the input. Lines starting with a semicolon are
comments and are not processed.

.. _knsupdate_options:

Options
.......

**-d**
  Enable debug messages.

**-h**, **--help**
  Print the program help.

**-k** *keyfile*
  Use the TSIG key stored in a file *keyfile* to authenticate the request. The
  file should contain the key in the same format, which is accepted by the
  **-y** option.

**-p** *port*
  Set the port to use for connections to the server (if not explicitly specified
  in the update). The default is 53.

**-r** *retries*
  The number of retries for UDP requests. The default is 3.

**-t** *timeout*
  The total timeout (for all UDP update tries) of the update request in seconds.
  The default is 12. If set to zero, the timeout is infinite.

**-v**
  Use a TCP connection.

**-V**, **--version**
  Print the program version.

**-y** [*alg*:]\ *name*:*key*
  Use the TSIG key with a name *name* to authenticate the request. The *alg*
  part specifies the algorithm (the default is hmac-sha256) and *key* specifies
  the shared secret encoded in Base64.

.. _knsupdate_commands:

Commands
........

**server** *name* [*port*]
  Specifies a receiving server of the dynamic update message. The *name* parameter
  can be either a host name or an IP address. If the *port* is not specified,
  the default port is used. The default port value can be controlled using
  the **-p** program option.

**local** *address* [*port*]
  Specifies outgoing *address* and *port*. If no local is specified, the
  address and port are set by the system automatically. The default port number
  is 0.

**zone** *name*
  Specifies that all updates are done within a zone *name*. If not used,
  the default zone is the root zone.

**origin** *name*
  Specifies fully qualified domain name suffix which is appended to non-fqd
  owners in update commands. The default origin is the root zone.

**class** *name*
  Sets *name* as the default class for all updates. If not used, the default
  class is IN.

**ttl** *value*
  Sets *value* as the default TTL (in seconds). If not used, the default value
  is 0.

**key** [*alg*:]\ *name* *key*
  Specifies the TSIG *key* named *name* to authenticate the request. An optional
  *alg* algorithm can be specified. This command has the same effect as
  the program option **-y**.

[**prereq**] **nxdomain** *name*
  Adds a prerequisite for a non-existing record owned by *name*.

[**prereq**] **yxdomain** *name*
  Adds a prerequisite for an existing record owned by *name*.

[**prereq**] **nxrrset** *name* [*class*] *type*
  Adds a prerequisite for a non-existing record of the *type* owned by *name*.
  Internet *class* is expected.

[**prereq**] **yxrrset** *name* [*class*] *type* [*data*]
  Adds a prerequisite for an existing record of the *type* owned by *name*
  with optional *data*. Internet *class* is expected.

[**update**] **add** *name* [*ttl*] [*class*] *type* *data*
  Adds a request to add a new resource record into the zone.
  Please note that if the *name* is not fully qualified domain name, the
  current origin name is appended to it.

[**update**] **del**\[**ete**] *name* [*ttl*] [*class*] [*type*] [*data*]
  Adds a request to remove all (or matching *class*, *type* or *data*)
  resource records from the zone. There is the same requirement for the *name*
  parameter as in **update add** command. The *ttl* item is ignored.

**show**
  Displays current content of the update message.

**send**
  Sends the current update message and cleans the list of updates.

**answer**
  Displays the last answer from the server.

**debug**
  Enable debugging. This command has the same meaning as the **-d** program option.

**quit**
  Quit the program.

.. _knsupdate_notes:

Notes
-----

Options **-k** and **-y** can not be used simultaneously.

Dnssec-keygen keyfile format is not supported. Use :manpage:`keymgr(8)` instead.

Zone name/server guessing is not supported if the zone name/server is not specified.

Empty line doesn't send the update.

.. _knsupdate_examples:

Examples
--------

1. Send one update of the zone example.com to the server 192.168.1.1. The update
   contains two new records::

     $ knsupdate
     > server 192.168.1.1
     > zone example.com.
     > origin example.com.
     > ttl 3600
     > add test1.example.com. 7200 A 192.168.2.2
     > add test2 TXT "hello"
     > show
     > send
     > answer
     > quit

.. _knsupdate_see_also:

See Also
--------

:manpage:`kdig(1)`, :manpage:`khost(1)`, :manpage:`keymgr(8)`.
