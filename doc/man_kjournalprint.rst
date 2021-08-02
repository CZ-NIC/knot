.. highlight:: console

kjournalprint – Knot DNS journal print utility
==============================================

Synopsis
--------

:program:`kjournalprint` [*options*] *zone_name*

Description
-----------

The program prints zone history stored in a journal database. As default,
changes are colored for terminal.

Options
.......

**-c** *configfile*
  Path to Knot configuration file.

**-C** *confdb*
  Path to Knot configuration database.

**-D** *journal*
  Path to journal database.

**-l**, **--limit** *limit*
  Limits the number of displayed changes.

**-s**, **--serial** *soa*
  Start at a specific SOA serial.

**-d**, **--debug**
  Debug mode brief output.

**-z**, **--zone-list**
  Instead of reading the journal, display the list of zones in the DB.
  (*zone_name* not needed)

**-H**, **--check**
  Enable additional journal semantic checks during printing.

**-x**, **--mono**
  Don't generate colorized output.

**-n**, **--no-color**
  An alias for **-x**. Use of this option is deprecated, it will be removed in the future.

**-X**, **--color**
  Force colorized output.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

Parameters
..........

*zone_name*
  A name of the zone to print the history for.

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

Examples
--------

Last (most recent) 5 changes without colors::

  $ kjournalprint -nl 5 /var/lib/knot/journal example.com.

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
