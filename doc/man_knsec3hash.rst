.. highlight:: console

knsec3hash – NSEC hash computation utility
==========================================

Synopsis
--------

:program:`knsec3hash` *salt* *algorithm* *iterations* *name*

:program:`knsec3hash` *algorithm* *flags* *iterations* *salt* *name*

Description
-----------

This utility generates a NSEC3 hash for a given domain name and parameters of NSEC3 hash.

Parameters
..........

*salt*
  Specifies a binary salt encoded as a hexadecimal string.

*algorithm*
  Specifies a hashing algorithm by number. Currently, the only supported algorithm is SHA-1 (number 1).

*iterations*
  Specifies the number of additional iterations of the hashing algorithm.

*name*
  Specifies the domain name to be hashed.

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

Examples
--------

::

  $ knsec3hash 1 0 10 c01dcafe knot-dns.cz
  7PTVGE7QV67EM61ROS9238P5RAKR2DM7 (salt=c01dcafe, hash=1, iterations=10)

::

  $ knsec3hash - 1 0 net
  A1RT98BS5QGC9NFI51S9HCI47ULJG6JH (salt=-, hash=1, iterations=0)

See Also
--------

:rfc:`5155` – DNS Security (DNSSEC) Hashed Authenticated Denial of Existence.

:manpage:`knotc(8)`, :manpage:`knotd(8)`.
