.. highlight:: console

kcatalogprint – Knot DNS catalog print utility
==============================================

Synopsis
--------

:program:`kcatalogprint` [*options*] *catalog_dir*

Description
-----------

The program prints zone catalog stored in a catalog database.

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

Parameters
..........

*catalog_dir*
  A path to the catalog database directory (not data.mdb file).

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
