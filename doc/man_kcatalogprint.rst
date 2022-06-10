.. highlight:: console

kcatalogprint – Knot DNS catalog print utility
==============================================

Synopsis
--------

:program:`kcatalogprint` [*config_option* *config_argument*] [*option*]

Description
-----------

The program prints zone catalog stored in a catalog database.

Config options
..............

**-c**, **--config** *file*
  Use a textual configuration file (default is :file:`@config_dir@/knot.conf`).

**-C**, **--confdb** *directory*
  Use a binary configuration database directory (default is :file:`@storage_dir@/confdb`).
  The default configuration database, if exists, has a preference to the default
  configuration file.

**-D**, **--dir** *path*
  Use specified catalog database path and default configuration.

Options
.......

**-a**, **--catalog**
  Filter the output by catalog zone name.

**-m**, **--member**
  Filter the output by member zone name.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
