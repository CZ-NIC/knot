# dnstap.m4

# dt_DNSTAP([action-if-true], [action-if-false])
# --------------------------------------------------------------------------
# Check for required dnstap libraries and add dnstap configure args.
AC_DEFUN([dt_DNSTAP],
[
  AC_ARG_ENABLE([dnstap],
    AS_HELP_STRING([--enable-dnstap],
                   [Enable dnstap support for kdig (requires fstrm, protobuf-c)]),
    [opt_dnstap=$enableval], [opt_dnstap=no])

  AS_IF([test "$STATIC_MODULE_dnstap" != "no" -o "$SHARED_MODULE_dnstap" != "no"],
        [opt_dnstap=yes])

  AS_IF([test "$opt_dnstap" != "no"],[
    AC_PATH_PROG([PROTOC_C], [protoc-c])
    AS_IF([test -z "$PROTOC_C"],[
      AC_MSG_ERROR([The protoc-c program was not found. Please install protobuf-c!])
      ])
    PKG_CHECK_MODULES([libfstrm], [libfstrm])
    PKG_CHECK_MODULES([libprotobuf_c], [libprotobuf-c >= 1.0.0])
    DNSTAP_CFLAGS="$libfstrm_CFLAGS $libprotobuf_c_CFLAGS"
    DNSTAP_LIBS="$libfstrm_LIBS $libprotobuf_c_LIBS"
    $1
  m4_ifvaln([$2], [else
    $2])dnl
  ])
])
