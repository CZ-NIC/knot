.. highlight:: console

kjournalprint – Knot DNS journal print utility
==============================================

Synopsis
--------

:program:`kjournalprint` [*parameters*] *journal* *zone_name*

Description
-----------

Program requires journal. As default, changes are colored for terminal.

Parameters
..........

**-n**, **--no-color**
  Removes changes coloring.

**-l**, **--limit** *limit*
  Limits the number of displayed changes.

**-t**, **--list-zones**
  Instead of reading jurnal, display the list of zones in the DB (*zone_name* not needed)

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

Journal
.......

Requires journal in the form of path/zone-name.db

Zone name
.........

Requires name of the zone contained in the journal.

Examples
--------

Last (*most recent*) 5 changes without colors
.............................................

::

  $ kjournalprint -nl 5 example.com.db example.com.

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
