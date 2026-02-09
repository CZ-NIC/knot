.. _mod-dnserr:

``dnserr`` — DNS Error Reporting
================================

The module implements :rfc:`9567` and can be used either to indicate support
for DNS error reporting or as a monitoring agent.

Example
-------

Use this configuration to tell resolvers that if they encounter an error
with `example.com`, they should send a report to `channel.example`.

::

   mod-dnserr:
     - id: report
       report-channel: channel.example

   zone:
     - domain: example.com
       module: mod-dnserr/report

Use this configuration on the server responsible for `channel.example`
to capture incoming error reports. Unique reports are cached to prevent log
flooding.

::

   mod-dnserr:
     - id: agent
       agent: on

   zone:
     - domain: channel.example
       module: mod-dnserr/agent

Module reference
----------------

::

 mod-dnserr:
   - id: STR
     report-channel: DNAME
     agent: BOOL
     cache-size: INT
     cache-lifetime: TIME

.. _mod-dnserr_id:

id
..

A module identifier.

.. _mod-dnserr_report-channel:

report-channel
..............

Enables the announcement of DNS error reporting to the specified channel.

*Default:* not set

.. _mod-dnserr_agent:

agent
.....

Enables monitoring agent mode. Received reports are logged to the server log.

*Default:* not set

.. _mod-dnserr_cache-size:

cache-size
..........

Size of the cache that stores unique reports to be logged.

*Default:* 1000

.. _mod-dnserr_cache-lifetime:

cache-lifetime
..............

Lifetime of the log cache in seconds.

*Default:* 10
