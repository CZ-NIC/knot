# KNOT_LIB_VERSION([library-name], [current], [revision], [age])
# --------------------------------------------------------------
# See https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html

AC_DEFUN([KNOT_LIB_VERSION],
[
  m4_define([LIBNAME], patsubst($1, [^lib], []))dnl
  AC_SUBST([$1_VERSION_INFO], ["-version-info $2:$3:$4"])
  AC_SUBST([$1_SOVERSION],    ["$2"])
  AS_CASE([$host_os],
     [darwin*], [AC_SUBST([$1_SONAME], ["$1.$2.dylib"])],
     [cygwin*], [AC_SUBST([$1_SONAME], [["cyg]LIBNAME[-$2.dll"]])],
     [msys*],   [AC_SUBST([$1_SONAME], [["msys-]LIBNAME[-$2.dll"]])],
     [*],       [AC_SUBST([$1_SONAME], ["$1.so.$2"])]
  )
])
