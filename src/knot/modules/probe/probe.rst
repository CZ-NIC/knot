.. _mod-probe:

``probe`` — Knot probe for query-response transfer analytics
============================================================

The module allows the server to send information about incoming and outgoing 
traffic through *unix* sockets. Data are sent over various channels (for each
server thread one channel) and these data can be collected by third party
software for future processing.

Example
-------

Default module configuration::

    template:
      - id: default
        global-module: mod-probe

Explicit module configuration::

    mod-probe:
      - id: custom
        prefix: knot-probe-

    template:
      - id: default
        module: mod-probe/custom

Module reference
----------------

::

 mod-probe:
   - id: STR
     prefix: STR

.. _mod-probe_id:

id
..

A module identifier.

.. _mod-probe_prefix:

prefix of unix socket
.....................

Set prefix of unix socket name (or subdir). Unix sockets are always stored in run-dir
and the final path will be specified as *<run-dir>/<prefix><id>.unix* where *<id>* is
channel identificator (hexadecimal number that represents identificator of thread).

*Default:* kprobe-

Client side
-----------

For third party software in *libknot* is API for receive data from probe. Definition of API function can be
found under *libknot/probe/client.h* header. Example of client can be found in file *samples/knot-probe-client.c*.
