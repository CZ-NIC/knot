.. highlight:: none

``kjournalprint`` – Knot DNS journal print utility
==================================================

Synopsis
--------

:program:`kjournalprint` [*config_option*] [*options*] *zone_name*

:program:`kjournalprint` [*config_option*] **-z**

Description
-----------

The program prints zone history stored in a journal database. As default,
changes are colored for terminal.

Parameters
..........

*zone_name*
  A name of the zone to print the history for.

Config options
..............

**-c**, **--config** *file*
  Use a textual configuration file (default is :file:`@config_dir@/knot.conf`).

**-C**, **--confdb** *directory*
  Use a binary configuration database directory (default is :file:`@storage_dir@/confdb`).
  The default configuration database, if exists, has a preference to the default
  configuration file.

**-D**, **--dir** *path*
  Use specified journal database path and default configuration.

Options
.......

**-z**, **--zone-list**
  Instead of reading the journal, display the list of zones in the DB.

**-l**, **--limit** *limit*
  Limits the number of displayed changes.

**-s**, **--serial** *soa*
  Start at a specific SOA serial.

**-M**, **--merge**
  Print the changesets merged into one changeset. If zone-in-journal is present,
  the stored contents with all the changesets applied will be printed.

**-H**, **--check**
  Enable additional journal semantic checks during printing.

**-d**, **--debug**
  Debug mode brief output.

**-x**, **--mono**
  Don't generate colorized output.

**-X**, **--color**
  Force colorized output.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version. The option **-VV** makes the program
  print the compile time configuration summary.

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

Examples
--------

Last (most recent) 5 changes without colors::

  $ kjournalprint -xl 5 /var/lib/knot/journal example.com.

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
