.. highlight:: none
.. _Requirements:

************
Requirements
************

Hardware
========

Knot DNS requirements are not very demanding for typical
installations, and a commodity server or a virtual solution will be
sufficient in most cases.

However, please note that there are some scenarios that will require
administrator's attention and a testing of exact requirements before
deploying Knot DNS to a production environment. These cases include deployment for a
large number of zones (DNS hosting), large number of records in one
or more zones (TLD) or large number of requests.

CPU requirements
----------------

Knot DNS scales with processing power and also with the number of
available cores/CPUs.

There is no lower bound on the CPU requirements, but it should support
memory barriers and CAS (i586 and newer).

Memory requirements
-------------------

Knot DNS implementation focuses on performance and thus can be quite
memory demanding. The rough estimate for memory requirements is
3 times the size of the zone in text format. Again this is only
an estimate and you are advised to do your own measurements before
deploying Knot DNS to production.

.. NOTE::
   To ensure uninterrupted serving of the zone, Knot DNS
   employs the Read-Copy-Update mechanism instead of locking and thus
   requires twice the amount of memory for the duration of incoming
   transfers.

Operating system
================

Knot DNS itself is written in a portable way, but it depends on
several libraries. Namely userspace-rcu, which could be a constraint
when it comes to the operating system support. Knot DNS can be compiled
and run on most UNIX-like systems, such as Linux, \*BSD, and OS X.
