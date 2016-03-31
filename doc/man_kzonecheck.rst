.. highlight:: console

kzonecheck – Knot DNS zone check tool
=====================================

Synopsis
--------

:program:`kzonecheck` [*options*] *zonefile*

Description
-----------

This utility checks zone similar to knotc zonecheck, but without running server.

Options
..........

**-o**, **--origin** *origin*
  The zone origin. If not specified the name of file or name without '.zone' ending is assumed to be the origin.

**-v**, **--verbose**
  Enable debug output.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

See Also
--------

:manpage:`knotc(8)`.
