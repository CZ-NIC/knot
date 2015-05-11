dnl Check to see if the C compiler is clang or llvm-gcc
dnl
AC_DEFUN([AX_CC_LLVM],[
  AC_REQUIRE([AC_PROG_CC])
  AC_MSG_CHECKING([whether C compiler has a LLVM backend])
  $CC -x c /dev/null -dM -E > conftest.txt 2>&1
  if grep "__llvm__" conftest.txt >/dev/null 2>&1; then
    CC_LLVM=yes
  else
    CC_LLVM=no
  fi
  AC_SUBST([CC_LLVM])
  AC_MSG_RESULT([$CC_LLVM])
  rm -f conftest.txt
  ])
