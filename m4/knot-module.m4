# KNOT_MODULE([module-name], [default], [non-shareable])
# ------------------------------------------------------
# Set Knot DNS module building

AC_DEFUN([KNOT_MODULE],
[
  AC_ARG_WITH([module-$1],
    AS_HELP_STRING([--with-module-$1=yes|shared|no], [Build '$1' module [default=$2]]),
    [module=$withval],
    [module=$2]
  )

  doc_modules="${doc_modules}.. include:: ../src/knot/modules/$1/$1.rst\n"

  STATIC_MODULE_$1=no
  SHARED_MODULE_$1=no
  AS_CASE([$module],
   [yes],    [STATIC_MODULE_$1=yes
              static_modules="${static_modules}$1 "
              static_modules_declars="${static_modules_declars}extern const knotd_mod_api_t knotd_mod_api_$1;\n"
              static_modules_init="${static_modules_init}\\\\\n\t{ &knotd_mod_api_$1 },"],
   [shared], [SHARED_MODULE_$1=yes
              shared_modules="${shared_modules}$1 "
              AS_IF([test "$3" = "non-shareable"],
                    [AC_MSG_ERROR([Module $1 cannot be shared])])],
   [no],     [],
   [*],      [AC_MSG_ERROR([Invalid value '$module' for --with-module-$1])]
  )
  AM_CONDITIONAL([STATIC_MODULE_$1], [test "$STATIC_MODULE_$1" = "yes"])
  AM_CONDITIONAL([SHARED_MODULE_$1], [test "$SHARED_MODULE_$1" = "yes"])
])
