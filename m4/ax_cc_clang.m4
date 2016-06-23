dnl Check to see if the C compiler is clang and which version it is
dnl
AC_DEFUN([AX_CC_CLANG],[
  AC_REQUIRE([AC_PROG_CC])
  AC_MSG_CHECKING([whether C compiler is clang])
  CC_CLANG_VERSION=$(
    $CC -x c -dM -E /dev/null | \
    $GREP '__clang_version__' | \
    $EGREP -o '[[0-9]]+\.[[0-9]]+\.[[0-9]]+'
  )
  AC_SUBST([CC_CLANG_VERSION])
  if test -n "$CC_CLANG_VERSION"; then
    AC_MSG_RESULT([$CC_CLANG_VERSION])
  else
    AC_MSG_RESULT([no])
  fi
  ])
