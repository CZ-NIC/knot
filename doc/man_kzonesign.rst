.. highlight:: console

kzonesign – DNSSEC signing utility
==================================

Synopsis
--------

:program:`kzonesign` *options* *zone_name*

Description
-----------

This utility reads the zone's zone file, signs the zone according to given
configuration file, and writes the signed zone file back.

Options
.......

**-c** *conf-file*
  Knot DNS configuration file (same as for knotd).
  *This option is obligatory.*

**-o** *outdir*
  Write the output zone file to different directory than configured.

**-R**
  Allow key roll-overs nad NSEC3 re-salt.

**-T** *timestamp*
  Sign the zone (and roll the keys) as if it would be specific timestamp now.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

Parameters
..........

*zone_name*
  A name of the zone to be signed.

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
