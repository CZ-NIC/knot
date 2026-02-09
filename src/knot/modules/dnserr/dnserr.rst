.. _mod-dnserr:

``dnserr`` — DNS Error Reporting
=========================================

The `mod-dnserr` module implements RFC-9567. It allows authoritative
DNS servers to communicate with clients (resolvers) to identify and log
DNS errors.

Example
-------

Use this configuration to tell resolvers that if they encounter an error
with `example.com`, they should send a report to `agent-domain.com`.

::

	mod-dnserr:
	  - id: default
	    send-report-channel: agent-domain.com

	zone:
	  - domain: example.com
	    file: example.com.zone
	    module: mod-dnserr/default

Use this configuration on the server responsible for `agent-domain.com`
to capture incoming error reports. The `log-cache-size`` tracks unique events
to prevent log flooding, and `log-timeout`` determines how often that cache is
flushed to log file.

::

	mod-dnserr:
	  - id: agent
	    log-report-channel: on
	    log-cache-size: 10000
	    log-timeout: 5s

	zone:
	  - domain: agent-domain.com
	    file: agent-domain.com.zone
	    module: mod-dnserr/agent



Module reference
----------------

::

    mod-dnserr:
      - id: STR
        send-report-channel: DNAME
        log-report-channel: BOOL
        log-cache-size: INT
        log-timeout: TIME

.. _mod-dnserr_id:

id
..

A module identifier.

.. _mod-dnserr_send-report-channel:

send-report-channel
...................

Define domain where resolvers should point error reports to.

*Default:* not set

.. _mod-dnserr_log-report-channel:

log-report-channel
..................

Specify zone that sould accept and log reported errors.

*Default:* not set

.. _mod-dnserr_log-cache-size:

log-cache-size
..............

Size of table that stores reports to be logged out.

*Default:* 1000

.. _mod-dnserr_log-timeout:

log-timeout
...........

Flush logs at this frequency.

*Default:* 10s
