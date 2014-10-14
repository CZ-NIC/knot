# KNOT_CHECK_HEADER([prefix], [name], [default], [header], [cflags], [libs])
# -----------------------------------------------------------------------------
# Check presence of a library by checking for a header file.
#
# - adds --enable-prefix configure flag
#
# - if $enable_prefix is yes or auto, checks for the header file
#
# - emits an error if $enable_prefix is yes and the header is not present
#
# - check can be overridden by setting prefix_CFLAGS and prefix_LIBS
#   environment variables
#
# Output variables: $enable_foo (yes or no), $foo_CFLAGS, and $foo_LIBS
#
AC_DEFUN([KNOT_CHECK_HEADER],
[
  AC_ARG_ENABLE([$1], AC_HELP_STRING([--enable-$1], [Support for $2 [default $3]]),
    [enable_][$1][=$enableval], [enable_][$1][=][$3])

  AC_ARG_VAR([$1][_CFLAGS], [C compiler flags for $2, overriding defaults])
  AC_ARG_VAR([$1][_LIBS], [linker flags for $2, overriding defaults])

  AS_CASE([$enable_][$1],
    [no], [
      [$1][_CFLAGS]=
      [$1][_LIBS]=
    ],
    [auto|yes], [
      AS_IF([test -n "$][$1][_LIBS"], [
        dnl: skip header check if environment variable is set
        [enable_][$1][=yes]
      ],[
        dnl: check for header
        AC_CHECK_HEADER([$4], [
          [enable_][$1]=yes
          [$1][_CFLAGS]=[$5]
          [$1][_LIBS]=[$6]
        ], [
          AS_IF([test "$enable_][$1][" = auto],
            [[enable_][$1]=no],
            [AC_MSG_ERROR([Header file "$4" for $2 not found])]
          )
        ])
      ])
    ],
    [AC_MSG_ERROR([Invalid value of --enable-$1])]
  )
])
