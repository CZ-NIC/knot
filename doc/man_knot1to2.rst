.. highlight:: console

knot1to2 – Knot DNS configuration conversion utility
====================================================

Synopsis
--------

:program:`knot1to2` [*options*] -i *file* -o *file*

Description
-----------

This utility generates Knot DNS configuration file version 2.x from configuration
file version 1.x.

Parameters
..........

**-i**, **--in** *file*
  Input configuration file (Knot version 1.x).

**-o**, **--out** *file*
  Output configuration file (Knot version 2.x).

Options
.......

**-r**, **--raw**
  Raw output, do not reformat via :program:`knotc`.

**-p**, **--path** *directory*
  Path to :program:`knotc` utility.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

See Also
--------

:manpage:`knotc(8)`, :manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
