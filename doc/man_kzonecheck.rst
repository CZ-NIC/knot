.. highlight:: console

kzonecheck – Knot DNS zone file checking tool
=============================================

.. _kzonecheck_synopsis:

Synopsis
--------

:program:`kzonecheck` [*options*] *filename*

.. _kzonecheck_description:

Description
-----------

The utility checks zone file syntax and runs semantic checks on the zone
content. The executed checks are the same as the checks run by the Knot
DNS server.

Please, refer to the ``semantic-checks`` configuration option in
:manpage:`knot.conf(5)` for the full list of available semantic checks.

.. _kzonecheck_options:

Options
.......

**-o**, **--origin** *origin*
  Zone origin. If not specified, the origin is determined from the file name
  (possibly removing the ``.zone`` suffix).

**-t**, **--time** *time*
  Current time specification. Use UNIX timestamp, YYYYMMDDHHmmSS
  format, or [+/-]\ *time*\ [unit] format, where unit can be **Y**, **M**,
  **D**, **h**, **m**, or **s**. Default is current UNIX timestamp.

**-v**, **--verbose**
  Enable debug output.

**-h**, **--help**
  Print the program help.

**-V**, **--version**
  Print the program version.

.. _kzonecheck_see_also:

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
