# Copyright (C) CZ.NIC, z.s.p.o. and contributors
# SPDX-License-Identifier: GPL-2.0-or-later
# For more information, see <https://www.knot-dns.cz/>

# Processes --with-sanitizer, --with-fuzzer, and --with-oss-fuzz flags, checks
# if the options are supported by the compiler, and sets the following
# variables accordingly:
#
# - sanitizer_CFLAGS  -fsanitize=...
# - fuzzer_CLAGS      -fsanitize=...
# - fuzzer_LDLAGS     -fsanitize=...

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

  # Default values
  AS_IF([test "$with_sanitizer" = "yes"], [ with_sanitizer=address,undefined ])
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
