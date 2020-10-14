.. highlight:: console

kjournalprint – Knot DNS journal print utility
==============================================

Synopsis
--------

:program:`kjournalprint` [*options*] *journal_dir* *zone_name*

Description
-----------

The program prints zone history stored in a journal database. As default,
changes are colored for terminal.

Options
.......

**-l**, **--limit** *limit*
  Limits the number of displayed changes.

**-s**, **--serial** *soa*
  Start at specific SOA serial.

**-d**, **--debug**
  Debug mode brief output.

**-n**, **--no-color**
  Removes changes coloring.

**-z**, **--zone-list**
  Instead of reading jurnal, display the list of zones in the DB.
  (*zone_name* not needed)

**-c**, **--check**
  Enable additional journal semantic checks during printing.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

Parameters
..........

*journal_dir*
  A path to the journal database directory.

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
