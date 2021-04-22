.. highlight:: console

kzonecheck – Knot DNS zone file checking tool
=============================================

Synopsis
--------

:program:`kzonecheck` [*options*] *filename*

Description
-----------

The utility checks zone file syntax and runs semantic checks on the zone
content. The executed checks are the same as the checks run by the Knot
DNS server.

Please, refer to the ``semantic-checks`` configuration option in
:manpage:`knot.conf(5)` for the full list of available semantic checks.

Parameters
..........

*filename*
  Path to the zone file to be checked. For reading from **stdin** use **/dev/stdin**
  or just **-**.

Options
.......

**-o**, **--origin** *origin*
  Zone origin. If not specified, the origin is determined from the file name
  (possibly removing the ``.zone`` suffix).

**-d**, **--dnssec** **on**\|\ **off**
  Also check DNSSEC-related records. The default is to decide based on the
  existence of a RRSIG for SOA.

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

Exit values
-----------

Exit status of 0 means successful operation. Any other exit status indicates
an error.

See Also
--------

:manpage:`knotd(8)`, :manpage:`knot.conf(5)`.
