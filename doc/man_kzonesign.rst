.. highlight:: console

kzonesign – DNSSEC signing utility
==================================

Synopsis
--------

:program:`kzonesign` [*options*] **-c** *conf_file* *zone_name*

Description
-----------

This utility reads the zone's zone file, signs the zone according to given
configuration, and writes the signed zone file back.

Options
.......

**-c**, **--config** *conf_file*
  Knot DNS configuration file (same as for knotd).

**-o**, **--outdir** *dir_name*
  Write the output zone file to the specified directory instead of the configured one.

**-r**, **--rollover**
  Allow key roll-overs and NSEC3 re-salt. In order to finish possible KSK submission,
  set the KSK's **active** timestamp to now (**+0**) using :doc:`keymgr<man_keymgr>`.

**-t**, **--time** *timestamp*
  Sign the zone (and roll the keys if necessary) as if it was at the time
  specified by timestamp.

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

:manpage:`knot.conf(5)`, :manpage:`keymgr(8)`.
