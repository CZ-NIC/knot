knsec3hash -- NSEC hash computation utility
===========================================

Synopsis
--------

:program:`knsec3hash` *salt* *alg* *iters* *dname*

Description
-----------

The utility generates NSEC3 hash for given domain name and parameters of NSEC3 hash.

Parameters
..........

`salt`
  Specifies binary salt encoded as a hexadecimal string.

`alg`
  Specifies hashing algorithm number. Currently the only supported algorithm is SHA-1 (number 1).

`iters`
  Specifies the number of additional iterations of the hashing algorithm.

`dname`
  Specifies the domain name to be hashed.

Example
-------

::

  $ knsec3hash c01dcafe 1 10 knot-dns.cz
  7PTVGE7QV67EM61ROS9238P5RAKR2DM7 (salt=c01dcafe, hash=1, iterations=10)

See Also
--------

:rfc:`5155` - DNS Security (DNSSEC) Hashed Authenticated Denial of Existence.

:manpage:`knotc(8)`, :manpage:`knotd(8)`.
