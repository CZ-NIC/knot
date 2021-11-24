.. _mod-probe:

``probe`` — DNS traffic probe
=============================

The module allows the server to send simplified information about regular DNS
traffic through *UNIX* sockets. The exported information consists of data blocks
where each data block (datagram) describes one query/response pair. The response
part can be empty. The receiver can be an arbitrary program using *libknot* interface
(C or Python). In case of high traffic, more channels (sockets) can be configured
to allow parallel processing.

Example
-------

Default module configuration::

   template:
     - id: default
       global-module: mod-probe

Per zone probe with 8 channels and maximum 1M logs per second limit::

   mod-probe:
     - id: custom
       prefix: /tmp/knot-probe
       channels: 8
       max-rate: 1000000

   zone:
     - domain: example.com.
       module: mod-probe/custom


Module reference
----------------

::

   mod-probe:
     - id: STR
       path: STR
       channels: INT
       max-rate: INT

.. _mod-probe_id:

id
..

A module identifier.

.. _mod-probe_path:

path
....

A directory path the UNIX sockets are located.

.. NOTE::
   It's recommended to use a directory with the execute permission restricted
   to the intended probe consumer process owner only.

*Default:* :ref:`rundir<server_rundir>`

.. _mod-probe_channels:

channels
........

Number of channels (UNIX sockets) the traffic is distributed to. In case of
high DNS traffic which is beeing processed by many UDP/XDP/TCP workers,
using more channels reduces the module overhead.

*Default:* 1

.. _mod-probe_max-rate:

max-rate
........

Maximum number of queries/replies per second the probe is allowed to transfer.
If the limit is exceeded, the over-limit traffic is ignored. Zero value means
no limit.

*Default:* 1000
