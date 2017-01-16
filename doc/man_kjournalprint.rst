.. highlight:: console

kjournalprint – Knot DNS journal print utility
==============================================

Synopsis
--------

:program:`kjournalprint` [*options*] *journal_db* *zone_name*

Description
-----------

The program prints zone history stored in a journal database. As default,
changes are colored for terminal.

Options
.......

**-l**, **--limit** *limit*
  Limits the number of displayed changes.

**-n**, **--no-color**
  Removes changes coloring.

**-z**, **--zone-list**
  Instead of reading jurnal, display the list of zones in the DB.
  (*zone_name* not needed)

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

Parameters
..........

*journal_db*
  A path to the journal database.

*zone_name*
  A name of the zone to print the history for.

Examples
--------

Last (most recent) 5 changes without colors::

  $ kjournalprint -nl 5 /var/lib/knot/journal example.com.

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
