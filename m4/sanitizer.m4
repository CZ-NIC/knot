# Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3, as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <https://www.gnu.org/licenses/>.

#
# Processes --with-sanitizer, --with-fuzzer, and --with-oss-fuzz flags, checks
# if the options are supported by the compiler, and sets the following
# variables accordingly:
#
# - sanitizer_CFLAGS  -fsanitize=...
# - fuzzer_CLAGS      -fsanitize=...
# - fuzzer_LDLAGS     -fsanitize=...
#

AC_DEFUN([AX_SANITIZER], [

  # Configure options
  AC_ARG_WITH([sanitizer],
    [AS_HELP_STRING([--with-sanitizer], [Compile with sanitizer [default=no]])],
    [],
    [with_sanitizer=no]
  )
  AC_ARG_WITH([fuzzer],
    [AS_HELP_STRING([--with-fuzzer], [Compile with libfuzzer [default=no]])],
    [],
    [with_fuzzer=no]
  )
  AC_ARG_WITH([oss-fuzz],
    [AS_HELP_STRING([--with-oss-fuzz], [Link for oss-fuzz environment [default=no]])],
    [],
    [with_oss_fuzz=no]
  )

  # Using -fsanitize=fuzzer requires clang >= 6.0
  AS_IF([test "$with_fuzzer" != "no"],[
    # Get clang version if empty
    AS_IF([test -z "$CC_CLANG_VERSION"],[AX_CC_CLANG])
    AX_COMPARE_VERSION([$CC_CLANG_VERSION],ge,[6.0],[],[
      AC_MSG_ERROR([clang >= 6.0 required for fuzzer])])])

  # Default values
  AS_IF([test "$with_sanitizer" = "yes"], [ with_sanitizer=address ])
  AS_IF([test "$with_fuzzer" = "yes"], [ with_fuzzer=fuzzer ])

  # Construct output variables
  sanitizer_CFLAGS=
  fuzzer_CFLAGS=
  fuzzer_LDFLAGS=
  AS_IF([test "$with_sanitizer" != "no"], [
      sanitizer_CFLAGS="-fsanitize=${with_sanitizer}"
  ])
  AS_IF([test "$with_fuzzer" != "no"], [
      fuzzer_CFLAGS="-fsanitize=${with_fuzzer}"
      fuzzer_LDFLAGS="-fsanitize=${with_fuzzer}"
  ])
  AC_SUBST(fuzzer_CFLAGS)
  AC_SUBST(fuzzer_LDFLAGS)

  # Test compiler support
  AS_IF([test -n "$sanitizer_CFLAGS" -o -n "$fuzzer_CFLAGS"], [
    save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $sanitizer_CFLAGS $fuzzer_CFLAGS"
    AC_MSG_CHECKING([whether compiler accepts '${sanitizer_CFLAGS} ${fuzzer_CFLAGS}'])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM()], [
      AC_MSG_RESULT([yes])
    ], [
      AC_MSG_RESULT([no])
      AC_MSG_ERROR([Options are not supported.])
    ])
    CFLAGS="$save_CFLAGS"
  ])

]) # AX_SANITIZER
