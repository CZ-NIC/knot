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
administrator's attention and some testing of exact requirements before
deploying Knot DNS to a production environment. These cases include
deployment for a large number of zones (DNS hosting), large number
of records in one or more zones (TLD), or large number of requests.

CPU requirements
----------------

The server scales with processing power and also with the number of
available cores/CPUs. Enabling Hyper-threading is convenient if supported.

There is no lower bound on the CPU requirements, but it should support
memory barriers and CAS (i586 and newer).

Network card
------------

The best results have been achieved with multi-queue network cards. The
number of multi-queues should equal the total number of CPU cores (with
Hyper-threading enabled).

Memory requirements
-------------------

The server implementation focuses on performance and thus can be quite
memory demanding. The rough estimate for memory requirements is
3 times the size of the zone in the plain-text format. Again this is only
an estimate and you are advised to do your own measurements before
deploying Knot DNS to production.

.. NOTE::
   To ensure uninterrupted serving of the zone, Knot DNS
   employs the Read-Copy-Update mechanism instead of locking and thus
   requires twice the amount of memory for the duration of incoming
   transfers.

Operating system
================

Knot DNS itself is written in a portable way and can be compiled
and run on most UNIX-like systems, such as Linux, \*BSD, and macOS.

Required libraries
==================

Knot DNS requires a few libraries to be available:

* libedit
* GnuTLS >= 3.3
* Userspace RCU >= 0.5.4
* lmdb >= 0.9.15

.. NOTE::
   The LMDB library is included with Knot DNS source code. However, linking
   with the system library is preferred.

Optional libraries
==================

International Domain Names support (IDNA2003 or IDNA2008) in kdig needs:

* libidn or libidn2

Systemd's startup notifications mechanism and journald logging need:

* libsystemd

Dnstap support in kdig and module dnstap need:

* fstrm (and protobuf-c if building from source code)

POSIX 1003.1e :manpage:`capabilites(7)` by sandboxing exposed threads.
Most rights are stripped from the exposed threads for security reasons.

* libcap-ng >= 0.6.4
