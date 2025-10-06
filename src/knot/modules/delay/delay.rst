.. _mod-delay:

``delay`` – delay the query response
====================================

A module for delaying response to a query.

Example
-------

   mod-delay:
     - id: delay_10ms
       delay: 10ms

   template:
     - id: default
       global-module: mod-delay/delay_10ms

The above configuration delays the response by 10ms.

Module reference
----------------

For delaying query response, use this module.

::

 mod-delay:
   - id: STR
     delay: INT
     all: BOOL

id
..

A module identifier.

.. _mod-dnstap_sink:

delay
....

Number of ms to delay the module call.
*Required*

all
........

The value indicates if all module call needs to be delayed or final response alone needs to be delayed.
If all module calls are delayed, then total time the query is delayed will be number of module hooks available * delay time.