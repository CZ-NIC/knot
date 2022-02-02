.. highlight:: console

kzonesign – DNSSEC signing utility
==================================

Synopsis
--------

:program:`kzonesign` [*config_option* *config_argument*] [*options*] *zone_name*

Description
-----------

This utility reads the zone's zone file, signs the zone according to given
configuration, and writes the signed zone file back. An alternative mode
is DNSSEC validation of the given zone. The signing or validation
can run in parallel if enabled in the configuration (see policy.signing-threads
and zone.adjust-threads).

Config options
..............

**-c**, **--config** *file*
  Use a textual configuration file (default is :file:`@config_dir@/knot.conf`).

**-C**, **--confdb** *directory*
  Use a binary configuration database directory (default is :file:`@storage_dir@/confdb`).
  The default configuration database, if exists, has a preference to the default
  configuration file.

Options
.......

**-o**, **--outdir** *dir_name*
  Write the output zone file to the specified directory instead of the configured one.

**-r**, **--rollover**
  Allow key roll-overs and NSEC3 re-salt. In order to finish possible KSK submission,
  set the KSK's **active** timestamp to now (**+0**) using :doc:`keymgr<man_keymgr>`.

**-v**, **--verify**
  Instead of (re-)signing the zone, just verify that the zone is correctly signed.

**-t**, **--time** *timestamp*
  Sign/verify the zone (and roll the keys if necessary) as if it was at the time
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
