# Copyright 2015-2017 CZ.NIC, z.s.p.o.
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
# with this program.  If not, see <http://www.gnu.org/licenses/>.

#
# Processes --with-sanitize= and --with-sanitize-coverage= flags, checks
# if the options are supported by the compiler, and sets the following
# variables accordingly:
#
# - sanitize_enabled          yes|no
# - sanitize_coverage_enabled yes|no
# - sanitize_fuzzer_enabled   yes|no
# - sanitize_CFLAGS           -fsanitize=... -fsanitize-coverage=...
#
AC_DEFUN([AX_SANITIZER], [

  # Configure options
  AC_ARG_WITH([sanitize],
    [AS_HELP_STRING([--with-sanitize], [Compile with sanitizer [default=no]])],
    [],
    [with_sanitize=no]
  )
  AC_ARG_WITH([sanitize-coverage],
    [AS_HELP_STRING([--with-sanitize-coverage], [Compile with sanitizer coverage [default=no]])],
    [],
    [with_sanitize_coverage=no]
  )
  AC_ARG_WITH([sanitize-fuzzer],
    [AS_HELP_STRING([--with-sanitize-fuzzer], [Compile with sanitizer fuzzer (require clang >= 6.0) [default=no]])], [ 
      # Enable SanitizerCoverage if needed by libFuzzer
      AS_IF([test "$with_sanitize_coverage" = "no"],[
        AC_MSG_NOTICE([Enabling sanitizer coverage because it's required for sanitizer fuzzer])
        with_sanitize_coverage=yes
      ])],
    [with_sanitize_fuzzer=no]
  )

  # Using -fsanitize=fuzzer requires clang >= 6.0
  AS_IF([test "$with_sanitize_fuzzer" != "no"],[
    # Get clang version if empty
    AS_IF([test -z "$CC_CLANG_VERSION"],[AX_CC_CLANG])
    AX_COMPARE_VERSION([$CC_CLANG_VERSION],ge,[6.0],[],[
      AC_MSG_ERROR([clang >= 6.0 required for sanitize fuzzer])])])

  # Default values
  AS_IF([test "$with_sanitize" = "yes"], [ with_sanitize=address ])
  AS_IF([test "$with_sanitize_fuzzer" = "yes"], [ with_sanitize_fuzzer=fuzzer-no-link ])
  AS_IF([test "$with_sanitize_coverage" = "yes"], [ with_sanitize_coverage=edge,indirect-calls,trace-pc-guard ])

  # Either --with-sanitize or --with-sanitize-fuzzer is needed for --with-sanitize-coverage
  AS_IF([test "$with_sanitize" = "no" -a "$with_sanitize_fuzzer" = "no" -a "$with_sanitize_coverage" != "no"],[
    AC_MSG_ERROR([--with-sanitize-coverage cannot be used without --with-sanitize or --with-sanitize-fuzzer])])

  # Construct output variables
  sanitize_enabled=no
  sanitize_coverage_enabled=no
  sanitize_fuzzer_enable=no
  sanitize_CFLAGS=
  AS_IF([test "$with_sanitize" != "no" -o "$with_sanitize_fuzzer" != "no"], [
    AS_IF([test "$with_sanitize" != "no"], [
      sanitize_enabled=yes
      AS_IF([test "$with_sanitize_fuzzer" != "no"], [ # --with-sanitize and --with-sanitize-fuzzer
        sanitize_CFLAGS="-fsanitize=${with_sanitize},${with_sanitize_fuzzer}"
        sanitize_fuzzer_enabled=yes
        ],[ # only --with-sanitize
        sanitize_CFLAGS="-fsanitize=${with_sanitize}"
        ])
      ],[ # only --with-sanitize-fuzzer
      AS_IF([test "$with_sanitize_fuzzer" != "no"], [
        sanitize_CFLAGS="-fsanitize=${with_sanitize_fuzzer}"
        sanitize_fuzzer_enabled=yes
        ])])
    AS_IF([test "$with_sanitize_coverage" != "no"], [
      sanitize_CFLAGS="$sanitize_CFLAGS -fsanitize-coverage=${with_sanitize_coverage}"
      sanitize_coverage_enabled=yes
    ])

    # Test compiler support
    save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $sanitize_CFLAGS"
    AC_MSG_CHECKING([whether compiler accepts '${sanitize_CFLAGS}' options])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM()], [
      AC_MSG_RESULT([yes])
    ], [
      AC_MSG_RESULT([no])
      AC_MSG_ERROR([Sanitizer options are not supported.])
    ])
    CFLAGS="$save_CFLAGS"
  ])

]) # AX_SANITIZER
