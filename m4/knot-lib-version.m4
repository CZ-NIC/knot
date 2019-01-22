# KNOT_LIB_VERSION([library-name], [current], [revision], [age])
# --------------------------------------------------------------
# See https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html

AC_DEFUN([KNOT_LIB_VERSION],
[
  AC_SUBST([$1_VERSION_INFO], ["-version-info $2:$3:$4"])
  AC_SUBST([$1_SO_VERSION],   ["$2"])
  AS_CASE([$host_os],
     [darwin*], [AC_SUBST([$1_SONAME], ["$1.$2.dylib"])],
     [*],       [AC_SUBST([$1_SONAME], ["$1.so.$2"])]
  )
])
