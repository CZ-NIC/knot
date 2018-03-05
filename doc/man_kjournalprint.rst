.. highlight:: console

kjournalprint – Knot DNS journal print utility
==============================================
.. _kjournalprint_synopsis:

Synopsis
--------

:program:`kjournalprint` [*options*] *journal_db* *zone_name*

.. _kjournalprint_description:

Description
-----------

The program prints zone history stored in a journal database. As default,
changes are colored for terminal.

.. _kjournalprint_options:

Options
.......

**-l**, **--limit** *limit*
  Limits the number of displayed changes.

**-d**, **--debug**
  Debug mode brief output.

**-n**, **--no-color**
  Removes changes coloring.

**-z**, **--zone-list**
  Instead of reading jurnal, display the list of zones in the DB.
  (*zone_name* not needed)

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

.. _kjournalprint_parameters:

Parameters
..........

*journal_db*
  A path to the journal database.

*zone_name*
  A name of the zone to print the history for.

.. _kjournalprint_examples:

Examples
--------

Last (most recent) 5 changes without colors::

  $ kjournalprint -nl 5 /var/lib/knot/journal example.com.

.. _kjournalprint_see_also:

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
