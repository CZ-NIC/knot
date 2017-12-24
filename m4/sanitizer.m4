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
# Processes --with-sanitize and --with-oss-fuzz flags, checks
# if the options are supported by the compiler, and sets the following
# variables accordingly:
#
# - sanitize_enabled          yes|no
# - sanitize_fuzzer_enabled   yes|no
# - sanitize_CFLAGS           -fsanitize=...
#
AC_DEFUN([AX_SANITIZER], [

  # Configure options
  AC_ARG_WITH([sanitize],
    [AS_HELP_STRING([--with-sanitize], [Compile with sanitizer [default=no]])],
    [],
    [with_sanitize=no]
  )
  AC_ARG_WITH([sanitize-fuzzer],
    [AS_HELP_STRING([--with-sanitize-fuzzer], [Compile with sanitizer fuzzer (require clang >= 6.0) [default=no]])],
    [],
    [with_sanitize_fuzzer=no]
  )
  AC_ARG_WITH([oss-fuzz],
    [AS_HELP_STRING([--with-oss-fuzz], [Link for oss-fuzz environment [default=no]])],
    [],
    [with_oss_fuzz=no]
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

  # Construct output variables
  sanitize_enabled=no
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
