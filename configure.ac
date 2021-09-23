AC_PREREQ([2.69])

m4_define([knot_VERSION_MAJOR], 3)dnl
m4_define([knot_VERSION_MINOR], 2)dnl
m4_define([knot_VERSION_PATCH], )dnl Leave empty if the master branch!
m4_include([m4/knot-version.m4])

AC_INIT([knot], [knot_PKG_VERSION], [knot-dns@labs.nic.cz])
AM_INIT_AUTOMAKE([foreign std-options subdir-objects no-dist-gzip dist-xz -Wall -Werror])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([src/knot])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_HOST

# Update library versions
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
KNOT_LIB_VERSION([libknot],    12, 0, 0)
KNOT_LIB_VERSION([libdnssec],   8, 0, 0)
KNOT_LIB_VERSION([libzscanner], 4, 0, 0)

AC_SUBST([KNOT_VERSION_MAJOR], knot_VERSION_MAJOR)
AC_SUBST([KNOT_VERSION_MINOR], knot_VERSION_MINOR)
AC_SUBST([KNOT_VERSION_PATCH], knot_VERSION_PATCH)

# Store ./configure parameters and CFLAGS
AC_DEFINE_UNQUOTED([CONFIGURE_PARAMS],["$*"],[Params passed to configure])
AC_DEFINE_UNQUOTED([CONFIGURE_CFLAGS],["$CFLAGS"],[Passed CFLAGS from environment])

AC_CONFIG_FILES([src/libknot/version.h
                 src/libdnssec/version.h
                 src/libzscanner/version.h])

# Automatically update release date based on NEWS
AC_PROG_SED
release_date=$($SED -n 's/^Knot DNS .* (\(.*\))/\1/p;q;' ${srcdir}/NEWS)
AC_SUBST([RELEASE_DATE], $release_date)

# Set compiler compatibility flags
AC_PROG_CC
AC_PROG_CPP_WERROR

# Set default CFLAGS
CFLAGS="$CFLAGS -Wall -Wshadow -Werror=format-security -Werror=implicit -Werror=attributes -Wstrict-prototypes"

AX_CHECK_COMPILE_FLAG("-fpredictive-commoning", [CFLAGS="$CFLAGS -fpredictive-commoning"], [], "-Werror")
AX_CHECK_LINK_FLAG(["-Wl,--exclude-libs,ALL"], [ldflag_exclude_libs="-Wl,--exclude-libs,ALL"], [ldflag_exclude_libs=""], "")
AC_SUBST([LDFLAG_EXCLUDE_LIBS], $ldflag_exclude_libs)

# Get processor byte ordering
AC_C_BIGENDIAN([endianity=big-endian], [endianity=little-endian])
AS_IF([test "$endianity" = "little-endian"],[
    AC_DEFINE([ENDIANITY_LITTLE], [1], [System is little-endian.])])

# Check if an archiver is available
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_PROG_INSTALL

# Initialize libtool
LT_INIT

# Use pkg-config
PKG_PROG_PKG_CONFIG
m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR], [AC_SUBST([pkgconfigdir], ['${libdir}/pkgconfig'])])
AC_CONFIG_FILES([src/knotd.pc
                 src/libknot.pc
                 src/libdnssec.pc
                 src/libzscanner.pc
                 ])

# Default directories
knot_prefix=$ac_default_prefix
AS_IF([test "$prefix" != NONE], [knot_prefix=$prefix])

run_dir="${localstatedir}/run/knot"
AC_ARG_WITH([rundir],
        AS_HELP_STRING([--with-rundir=path], [Path to run-time variable data (pid, sockets...). [default=LOCALSTATEDIR/run/knot]]),
        [run_dir=$withval])
AC_SUBST(run_dir)

storage_dir="${localstatedir}/lib/knot"
AC_ARG_WITH([storage],
        AS_HELP_STRING([--with-storage=path], [Default storage directory (slave zones, persistent data). [default=LOCALSTATEDIR/lib/knot]]),
        [storage_dir=$withval])
AC_SUBST(storage_dir)

config_dir="${sysconfdir}/knot"
AC_ARG_WITH([configdir],
        AS_HELP_STRING([--with-configdir=path], [Default directory for configuration. [default=SYSCONFDIR/knot]]),
        [config_dir=$withval])
AC_SUBST(config_dir)

module_dir=
module_instdir="${libdir}/knot/modules-${KNOT_VERSION_MAJOR}.${KNOT_VERSION_MINOR}"
AC_ARG_WITH([moduledir],
        AS_HELP_STRING([--with-moduledir=path], [Path to auto-loaded dynamic modules. [default not set]]),
        [module_dir=$withval module_instdir=$module_dir])
AC_SUBST(module_instdir)
AC_SUBST(module_dir)

# Build Knot DNS daemon
AC_ARG_ENABLE([daemon],
    AS_HELP_STRING([--disable-daemon], [Don't build Knot DNS main daemon]), [], [enable_daemon=yes])
AM_CONDITIONAL([HAVE_DAEMON], [test "$enable_daemon" = "yes"])

# Build Knot DNS modules
AC_ARG_ENABLE([modules],
    AS_HELP_STRING([--disable-modules], [Don't build Knot DNS modules]), [], [enable_modules=yes])

# Build Knot DNS utilities
AC_ARG_ENABLE([utilities],
    AS_HELP_STRING([--disable-utilities], [Don't build Knot DNS utilities]), [], [enable_utilities=yes])
AM_CONDITIONAL([HAVE_UTILS], [test "$enable_utilities" = "yes"])

# Build Knot DNS documentation
AC_ARG_ENABLE([documentation],
    AS_HELP_STRING([--disable-documentation], [Don't build Knot DNS documentation]), [], [enable_documentation=yes])
AM_CONDITIONAL([HAVE_DOCS], [test "$enable_documentation" = "yes"])

AM_CONDITIONAL([HAVE_LIBUTILS], test "$enable_utilities" != "no" -o \
                                     "$enable_daemon" != "no")
######################
# Generic dependencies
######################

AC_ARG_ENABLE([fastparser],
    AS_HELP_STRING([--disable-fastparser], [Disable use of fast zone parser]),
    [], [AS_IF([test -d ".git"], [enable_fastparser=no], [enable_fastparser=yes])]
)
AM_CONDITIONAL([FAST_PARSER], [test "$enable_fastparser" = "yes"])

# GnuTLS crypto backend
PKG_CHECK_MODULES([gnutls], [gnutls >= 3.3], [
    save_CFLAGS=$CFLAGS
    save_LIBS=$LIBS
    CFLAGS="$CFLAGS $gnutls_CFLAGS"
    LIBS="$LIBS $gnutls_LIBS"

    AC_CHECK_FUNC([gnutls_pkcs11_copy_pubkey], [enable_pkcs11=yes], [enable_pkcs11=no])
    AS_IF([test "$enable_pkcs11" = yes],
        [AC_DEFINE([ENABLE_PKCS11], [1], [PKCS #11 support available])])

    AC_CHECK_DECL([GNUTLS_PK_EDDSA_ED25519],
        [AC_DEFINE([HAVE_ED25519], [1], [GnuTLS ED25519 support available])
         enable_ed25519=yes],
        [enable_ed25519=no],
        [#include <gnutls/gnutls.h>])

    AC_CHECK_DECL([GNUTLS_SIGN_EDDSA_ED448],
        [AC_DEFINE([HAVE_ED448], [1], [GnuTLS ED448 support available])
         enable_ed448=yes],
        [enable_ed448=no],
        [#include <gnutls/gnutls.h>])

    AC_CHECK_DECL([GNUTLS_PRIVKEY_FLAG_REPRODUCIBLE],
        [AC_DEFINE([HAVE_GNUTLS_REPRODUCIBLE], [1], [GnuTLS reproducible signing available])
         # Ensure the version is at least 3.6.10
         AC_CHECK_FUNC([gnutls_aead_cipher_encryptv2], [enable_repro_signing=yes], [enable_repro_signing=no])],
        [enable_repro_signing=no],
        [#include <gnutls/abstract.h>])

    AC_CHECK_FUNC([gnutls_privkey_sign_data2],
        [AC_DEFINE([HAVE_SIGN_DATA2], [1], [gnutls_privkey_sign_data2 available])])

    AC_CHECK_FUNC([gnutls_privkey_export_x509],
        [AC_DEFINE([HAVE_EXPORT_X509], [1], [gnutls_privkey_export_x509 available])])

    AC_CHECK_FUNC([gnutls_memset],
        [AC_DEFINE([HAVE_GNUTLS_MEMSET], [1], [gnutls_memset available])
         gnutls_memset=yes], [gnutls_memset=no])

    AC_CHECK_FUNC([gnutls_early_cipher_get], [gnutls_quic=yes], [gnutls_quic=no])

    CFLAGS=$save_CFLAGS
    LIBS=$save_LIBS
])
AM_CONDITIONAL([ENABLE_PKCS11], [test "$enable_pkcs11" = "yes"])

AC_ARG_ENABLE([recvmmsg],
   AS_HELP_STRING([--enable-recvmmsg=auto|yes|no], [enable recvmmsg() network API [default=auto]]),
   [], [enable_recvmmsg=auto])

AS_CASE([$enable_recvmmsg],
   [auto|yes],[
      AC_CHECK_FUNC([recvmmsg],
                    [AC_CHECK_FUNC([sendmmsg],[enable_recvmmsg=yes],[enable_recvmmsg=no])],
                    [enable_recvmmsg=no])],
   [no],[],
   [*], [AC_MSG_ERROR([Invalid value of --enable-recvmmsg.]
 )])

AS_IF([test "$enable_recvmmsg" = yes],[
   AC_DEFINE([ENABLE_RECVMMSG], [1], [Use recvmmsg().])])

# XDP support
AC_ARG_ENABLE([xdp],
   AS_HELP_STRING([--enable-xdp=auto|yes|no], [enable eXpress Data Path [default=auto]]),
   [], [enable_xdp=auto])

AS_CASE([$enable_xdp],
   [auto], [PKG_CHECK_MODULES([libbpf], [libbpf >= 0.0.6], [enable_xdp=yes], [enable_xdp=no])],
   [yes], [PKG_CHECK_MODULES([libbpf], [libbpf >= 0.0.6], [enable_xdp=yes],
             [PKG_CHECK_MODULES([libelf], [libelf],
                [AC_CHECK_FUNC([reallocarray],
                   [enable_xdp=embedded
                    embedded_libbpf_CFLAGS="-I\$(top_srcdir)/src/contrib/libbpf/include -I\$(top_srcdir)/src/contrib/libbpf/include/uapi"
                    embedded_libbpf_LIBS=$libelf_LIBS
                    libbpf_CFLAGS="-I\$(top_srcdir)/src/contrib/libbpf -I\$(top_srcdir)/src/contrib/libbpf/include/uapi"],
                   [enable_xdp=no
                    AC_MSG_WARN([reallocarray not available])])],
                [AC_MSG_ERROR([libelf is required])])])],
   [no], [],
   [*], [AC_MSG_ERROR([Invalid value of --enable-xdp.])]
)
AM_CONDITIONAL([EMBEDDED_LIBBPF], [test "$enable_xdp" = "embedded"])
AM_CONDITIONAL([ENABLE_XDP], [test "$enable_xdp" != "no"])
AC_SUBST([embedded_libbpf_CFLAGS])
AC_SUBST([embedded_libbpf_LIBS])
AC_SUBST([libbpf_CFLAGS])
AC_SUBST([libbpf_LIBS])

AS_IF([test "$enable_xdp" != "no"],[
    AC_DEFINE([ENABLE_XDP], [1], [Use eXpress Data Path.])])

# Reuseport support
AS_CASE([$host_os],
  [freebsd*], [reuseport_opt=SO_REUSEPORT_LB],
  [*], [reuseport_opt=SO_REUSEPORT],
)

AC_ARG_ENABLE([reuseport],
  AS_HELP_STRING([--enable-reuseport=auto|yes|no],
                 [enable SO_REUSEPORT(_LB) support [default=auto]]),
  [], [enable_reuseport=auto]
)

AS_CASE([$enable_reuseport],
  [auto], [
    AS_CASE([$host_os],
      [freebsd*|linux*], [AC_CHECK_DECL([$reuseport_opt],
                                        [enable_reuseport=yes],
                                        [enable_reuseport=no],
                                        [#include <sys/socket.h>
                                        ])],
      [*], [enable_reuseport=no]
    )],
  [yes], [AC_CHECK_DECL([$reuseport_opt], [],
                        [AC_MSG_ERROR([SO_REUSEPORT(_LB) not supported.])],
                        [#include <sys/socket.h>
                        ])],
  [no], [],
  [*], [AC_MSG_ERROR([Invalid value of --enable-reuseport.])]
)

AS_IF([test "$enable_reuseport" = yes],[
   AC_DEFINE([ENABLE_REUSEPORT], [1], [Use SO_REUSEPORT(_LB).])])

#########################################
# Dependencies needed for Knot DNS daemon
#########################################

# Systemd integration
AC_ARG_ENABLE([systemd],
    AS_HELP_STRING([--enable-systemd=auto|yes|no], [enable systemd integration [default=auto]]),
    [enable_systemd="$enableval"], [enable_systemd=auto])

AS_IF([test "$enable_daemon" = "yes"],[

AS_IF([test "$enable_systemd" != "no"],[
  AS_CASE([$enable_systemd],
    [auto],[PKG_CHECK_MODULES([systemd], [libsystemd], [enable_systemd=yes], [
            PKG_CHECK_MODULES([systemd], [libsystemd-daemon libsystemd-journal], [enable_systemd=yes], [enable_systemd=no])])],
    [yes],[PKG_CHECK_MODULES([systemd], [libsystemd], [], [
            PKG_CHECK_MODULES([systemd], [libsystemd-daemon libsystemd-journal])])],
    [*],[AC_MSG_ERROR([Invalid value of --enable-systemd.])])
    ])

AS_IF([test "$enable_systemd" = "yes"],[
  AC_DEFINE([ENABLE_SYSTEMD], [1], [Use systemd integration.])
  AC_CHECK_HEADER([systemd/sd-bus.h],
                  [AC_DEFINE([ENABLE_DBUS], [1], [systemd D-Bus available])],
                  [enable_systemd="yes (without D-Bus)"])
])

]) dnl enable_daemon

# Socket polling method
socket_polling=
AC_ARG_WITH([socket-polling],
  AS_HELP_STRING([--with-socket-polling=auto|poll|epoll|kqueue|libkqueue],
                 [Use specific socket polling method [default=auto]]),
  [socket_polling=$withval], [socket_polling=auto]
)

AS_CASE([$socket_polling],
  [auto], [AC_CHECK_FUNCS([kqueue],
             [AC_DEFINE([HAVE_KQUEUE], [1], [kqueue available])
              socket_polling=kqueue],
             [AC_CHECK_FUNCS([epoll_create],
                [AC_DEFINE([HAVE_EPOLL], [1], [epoll available])
                 socket_polling=epoll],
                [socket_polling=poll])])],
  [poll], [socket_polling=poll],
  [epoll], [AC_CHECK_FUNCS([epoll_create],
              [AC_DEFINE([HAVE_EPOLL], [1], [epoll available])
               socket_polling=epoll],
              [AC_MSG_ERROR([epoll not available.])])],
  [kqueue], [AC_CHECK_FUNCS([kqueue],
               [AC_DEFINE([HAVE_KQUEUE], [1], [kqueue available])
                socket_polling=kqueue],
               [AC_MSG_ERROR([kqueue not available.])])],
  [libkqueue], [PKG_CHECK_MODULES([libkqueue], [libkqueue],
                  [AC_DEFINE([HAVE_KQUEUE], [1], [libkqueue available])
                   socket_polling=libkqueue],
                  [AC_MSG_ERROR([libkqueue not available.])])],
  [*], [AC_MSG_ERROR([Invalid value of --socket-polling.])]
)

# Alternative memory allocator
malloc_LIBS=
AC_ARG_WITH([memory-allocator],
  AS_HELP_STRING([--with-memory-allocator=auto|LIBRARY],
                 [Use specific memory allocator for the server (e.g. jemalloc) [default=auto]]),
  AS_CASE([$withval],
    [auto], [],
    [*],    [malloc_LIBS="-l$withval"]
  )
  with_memory_allocator=[$withval]
)
AS_IF([test "$with_memory_allocator" = ""], [with_memory_allocator="auto"])
AC_SUBST([malloc_LIBS])

dnl Check for userspace-rcu library
AC_ARG_WITH(urcu,
[  --with-urcu=DIR        where to find userspace-rcu library])

AS_IF([test "$enable_daemon" = "yes"],[

AS_IF([test "$with_urcu" != "no"], [
  PKG_CHECK_MODULES([liburcu], liburcu, [
    liburcu_PKGCONFIG="liburcu >= 0.4.0"
    AC_SUBST([liburcu_PKGCONFIG])
    with_urcu=yes
  ],[
    for try_urcu in "$with_urcu" "" "/usr/local"; do
      save_LIBS="$LIBS"
      save_CPPFLAGS="$CPPFLAGS"

      AS_IF([test -d "$try_urcu"], [
        liburcu_CFLAGS="-I$try_urcu/include"
        liburcu_LIBS="-L$try_urcu/lib"
      ],[
        liburcu_CFLAGS=""
        liburcu_LIBS=""
      ])

      CPPFLAGS="$CPPFLAGS $liburcu_CFLAGS"
      LIBS="$LIBS $liburcu_LIBS"

      AC_SEARCH_LIBS([rcu_set_pointer_sym], [urcu], [
        with_urcu=yes
        liburcu_LIBS="$liburcu_LIBS -lurcu"
        AC_SUBST([liburcu_CFLAGS])
        AC_SUBST([liburcu_LIBS])
        break
      ],[
        CPPFLAGS="$save_CPPFLAGS"
        LIBS="$save_LIBS"
        with_urcu=no
        # do not cache result of AC_SEARCH_LIBS test
        unset ac_cv_search_rcu_set_pointer_sym
      ])
    done
    CPPFLAGS="$save_CPPFLAGS"
    LIBS="$save_LIBS"

    AS_IF([test "$with_urcu" = "no"],[
      AC_MSG_ERROR([liburcu is required])
      ])
  ])
])

])

static_modules=""
shared_modules=""
static_modules_declars=""
static_modules_init=""
doc_modules=""

KNOT_MODULE([cookies],     "yes")
KNOT_MODULE([dnsproxy],    "yes", "non-shareable")
KNOT_MODULE([dnstap],      "no")
KNOT_MODULE([geoip],       "yes")
KNOT_MODULE([noudp],       "yes")
KNOT_MODULE([onlinesign],  "yes", "non-shareable")
KNOT_MODULE([probe],       "yes")
KNOT_MODULE([queryacl],    "yes")
KNOT_MODULE([rrl],         "yes")
KNOT_MODULE([stats],       "yes")
KNOT_MODULE([synthrecord], "yes")
KNOT_MODULE([whoami],      "yes")

AC_SUBST([STATIC_MODULES_DECLARS], [$(printf "$static_modules_declars")])
AM_SUBST_NOTMAKE([STATIC_MODULES_DECLARS])
AC_SUBST([STATIC_MODULES_INIT], [$(printf "$static_modules_init")])
AM_SUBST_NOTMAKE([STATIC_MODULES_INIT])
AC_SUBST([DOC_MODULES], [$(printf "$doc_modules")])
AM_SUBST_NOTMAKE([DOC_MODULES])

# Check for Dnstap
AC_ARG_ENABLE([dnstap],
  AS_HELP_STRING([--enable-dnstap], [Enable dnstap support for kdig (requires fstrm, protobuf-c)]),
  [], [enable_dnstap=no])

AS_IF([test "$enable_dnstap" != "no" -o "$STATIC_MODULE_dnstap" != "no" -o "$SHARED_MODULE_dnstap" != "no"],[
  AC_PATH_PROG([PROTOC_C], [protoc-c])
  AS_IF([test -z "$PROTOC_C"],[
    AC_MSG_ERROR([The protoc-c program was not found. Please install protobuf-c!])
  ])
  PKG_CHECK_MODULES([libfstrm], [libfstrm])
  PKG_CHECK_MODULES([libprotobuf_c], [libprotobuf-c >= 1.0.0])
  AC_SUBST([DNSTAP_CFLAGS], ["$libfstrm_CFLAGS $libprotobuf_c_CFLAGS"])
  AC_SUBST([DNSTAP_LIBS], ["$libfstrm_LIBS $libprotobuf_c_LIBS"])
])

AS_IF([test "$enable_dnstap" != "no"],[
  AC_DEFINE([USE_DNSTAP], [1], [Define to 1 to enable dnstap support for kdig])
])
AM_CONDITIONAL([HAVE_DNSTAP], test "$enable_dnstap" != "no")

AM_CONDITIONAL([HAVE_LIBDNSTAP], test "$enable_dnstap" != "no" -o \
                                      "$STATIC_MODULE_dnstap" != "no" -o \
                                      "$SHARED_MODULE_dnstap" != "no")
# MaxMind DB for the GeoIP module
AC_ARG_ENABLE([maxminddb],
    AS_HELP_STRING([--enable-maxminddb=auto|yes|no], [enable MaxMind DB [default=auto]]),
    [enable_maxminddb="$enableval"], [enable_maxminddb=auto])

AS_IF([test "$enable_daemon" = "no"],[enable_maxminddb=no])
AS_CASE([$enable_maxminddb],
  [no],[],
  [auto],[PKG_CHECK_MODULES([libmaxminddb], [libmaxminddb], [enable_maxminddb=yes], [enable_maxminddb=no])],
  [yes], [PKG_CHECK_MODULES([libmaxminddb], [libmaxminddb])],
  [*],[
    save_CFLAGS="$CFLAGS"
    save_LIBS="$LIBS"
    AS_IF([test "$enable_maxminddb" != ""],[
      LIBS="$LIBS -L$enable_maxminddb"
      CFLAGS="$CFLAGS -I$enable_maxminddb/include"
      ])
    AC_SEARCH_LIBS([MMDB_open], [maxminddb], [
      AS_IF([test "$enable_maxminddb" != ""], [
        libmaxminddb_CFLAGS="-I$enable_maxminddb/include"
        libmaxminddb_LIBS="-L$enable_maxminddb -lmaxminddb"
  ],[
  libmaxminddb_CFLAGS=""
  libmaxminddb_LIBS="$ac_cv_search_MMDB_open"
        ])
      ],[AC_MSG_ERROR("not found in `$enable_maxminddb'")])
    CFLAGS="$save_CFLAGS"
    LIBS="$save_LIBS"
    AC_SUBST([libmaxminddb_CFLAGS])
    AC_SUBST([libmaxminddb_LIBS])
    enable_maxminddb=yes
    ])

AS_IF([test "$enable_maxminddb" = yes], [AC_DEFINE([HAVE_MAXMINDDB], [1], [Define to 1 to enable MaxMind DB.])])
AM_CONDITIONAL([HAVE_MAXMINDDB], [test "$enable_maxminddb" = yes])

AC_ARG_WITH([lmdb],
  [AS_HELP_STRING([--with-lmdb=DIR], [explicit location where to find LMDB])]
)
PKG_CHECK_MODULES([lmdb], [lmdb >= 0.9.15], [], [
  save_CPPFLAGS=$CPPFLAGS
  save_LIBS=$LIBS

  have_lmdb=no

  for try_lmdb in "$with_lmdb" "" "/usr/local" "/usr/pkg"; do
    AS_IF([test -d "$try_lmdb"], [
      lmdb_CFLAGS="-I$try_lmdb/include"
      lmdb_LIBS="-L$try_lmdb/lib"
    ],[
      lmdb_CFLAGS=""
      lmdb_LIBS=""
    ])

    CPPFLAGS="$save_CPPFLAGS $lmdb_CFLAGS"
    LIBS="$save_LIBS $lmdb_LIBS"

    AC_SEARCH_LIBS([mdb_txn_id], [lmdb], [
      have_lmdb=yes
      lmdb_LIBS="$lmdb_LIBS -llmdb"
      AC_SUBST([lmdb_CFLAGS])
      AC_SUBST([lmdb_LIBS])
      break
    ])

    # do not cache result of AC_SEARCH_LIBS test
    unset ac_cv_search_mdb_txn_id
  done

  CPPFLAGS="$save_CPPFLAGS"
  LIBS="$save_LIBS"

  AS_IF([test "$have_lmdb" = "no"], [
    AC_MSG_ERROR([lmdb library not found])
  ])
])

# LMDB mapping sizes
conf_mapsize_default=500
AC_ARG_WITH([conf_mapsize],
    AS_HELP_STRING([--with-conf-mapsize=NUM], [Configuration DB mapsize in MiB [default=$conf_mapsize_default]]),
    [conf_mapsize=$withval],[conf_mapsize=$conf_mapsize_default])

AS_CASE([$conf_mapsize],
    [yes],[conf_mapsize=$conf_mapsize_default],
    [no], [AC_MSG_ERROR([conf_mapsize must be a number])],
    [*],  [AS_IF([test $conf_mapsize != $(( $conf_mapsize + 0 ))],
                 [AC_MSG_ERROR(conf_mapsize must be an integer number)])])
AC_DEFINE_UNQUOTED([CONF_MAPSIZE], [$conf_mapsize], [Configuration DB mapsize.])
AC_SUBST(conf_mapsize)

# libedit
AS_IF([test "$enable_daemon" = "yes" -o "$enable_utilities" = "yes"], [
  PKG_CHECK_MODULES([libedit], [libedit], [with_libedit=yes], [
    with_libedit=no
    AC_CHECK_HEADER([histedit.h], [
      # workaround for OpenBSD
      AS_CASE([$host_os],
        [openbsd*], [libedit_deps=-lcurses],
        [libedit_deps=]
      )
      AC_CHECK_LIB([edit], [el_init], [
        with_libedit=yes
        libedit_CFLAGS=
        libedit_LIBS="-ledit $libedit_deps"
        ], [], [$libedit_deps]
      )
    ])
  ])
  AS_IF([test "$with_libedit" != "yes"], [
    AC_MSG_ERROR([libedit not found])
  ])
], [
  with_libedit=no
  libedit_CFLAGS=
  libedit_LIBS=
])

############################################
# Dependencies needed for Knot DNS utilities
############################################

dnl Check for libidn.
AC_ARG_WITH(libidn,
  AS_HELP_STRING([--with-libidn=[DIR]], [Support IDN (needs GNU libidn2 or libidn)]),
  with_libidn=$withval,
  with_libidn=yes
)

dnl Check for libnghttp2.
AC_ARG_WITH(libnghttp2,
  AS_HELP_STRING([--with-libnghttp2=[DIR]], [Support DoH (needs libnghttp2)]),
  with_libnghttp2=$withval,
  with_libnghttp2=yes
)

dnl Check for libngtcp2.
AC_ARG_WITH(libngtcp2,
  AS_HELP_STRING([--with-libngtcp2=[DIR|embedded]], [Support DoQ (needs libngtcp2, gnutls >= 3.7.2)]),
  with_libngtcp2=$withval,
  with_libngtcp2=yes
)

AS_IF([test "$enable_utilities" = "yes"], [
  AS_IF([test "$with_libidn" != "no"], [
    PKG_CHECK_MODULES([libidn2], [libidn2 >= 2.0.0], [
      with_libidn=libidn2
      AC_DEFINE([LIBIDN], [1], [Define to 1 to enable IDN support])
      AC_DEFINE([LIBIDN_HEADER], [<idn2.h>], [Define to proper libidn header])
    ], [
      PKG_CHECK_MODULES([libidn], [libidn >= 0.0.0], [
        with_libidn=libidn
        AC_DEFINE([LIBIDN], [1], [Define to 1 to enable IDN support])
        AC_DEFINE([LIBIDN_HEADER], [<idna.h>], [Define to proper libidn header])
      ], [
        with_libidn=no
        AC_MSG_WARN([libidn2 or libidn not found])
      ])
    ])
  ])

  AS_IF([test "$with_libnghttp2" != "no"], [
    PKG_CHECK_MODULES([libnghttp2], [libnghttp2], [
      with_libnghttp2=libnghttp2
      AC_DEFINE([LIBNGHTTP2], [1], [Define to 1 to enable DoH support])
    ], [
      with_libnghttp2=no
      AC_MSG_WARN([libnghttp2 not found])
    ])
  ])

  AS_IF([test "$with_libngtcp2" != "no"], [
    AS_IF([test "$with_libngtcp2" = "embedded"], [
      AS_IF([test "$gnutls_quic" = "yes"],
        [embedded_libngtcp2_CFLAGS="-I\$(top_srcdir)/src/contrib/libngtcp2 -I\$(top_srcdir)/src/contrib/libngtcp2/ngtcp2/lib"
         embedded_libngtcp2_LIBS=$libelf_LIBS
         libngtcp2_CFLAGS="-I\$(top_srcdir)/src/contrib/libngtcp2"],
        [with_libngtcp2=no
         AC_MSG_ERROR([gnutls >= 3.7.2 is required])])], [
      PKG_CHECK_MODULES([libngtcp2], [libngtcp2 libngtcp2_crypto_gnutls],
        [with_libngtcp2=libngtcp2],
        [with_libngtcp2=no
         AC_MSG_WARN([libngtcp2 not found])])])
  ])
  AM_CONDITIONAL([EMBEDDED_LIBNGTCP2], [test "$with_libngtcp2" = "embedded"])
  AC_SUBST([embedded_libngtcp2_CFLAGS])
  AC_SUBST([embedded_libngtcp2_LIBS])
  AC_SUBST([libngtcp2_CFLAGS])
  AC_SUBST([libngtcp2_LIBS])

  AS_IF([test "$with_libngtcp2" != "no"], [
    AC_DEFINE([LIBNGTCP2], [1], [Define to 1 to enable DoQ support based on GnuTLS])])

  AS_IF([test "$enable_xdp" != "no"], [
    PKG_CHECK_MODULES([libmnl], [libmnl], [], [
      AC_MSG_ERROR([libmnl not found])
    ])
  ])
]) # Knot DNS utilities dependencies

AC_ARG_ENABLE([cap-ng],
    AS_HELP_STRING([--enable-cap-ng=auto|no], [enable POSIX capabilities [default=auto]]),
    [enable_cap_ng="$enableval"], [enable_cap_ng=auto])

AS_IF([test "$enable_daemon" = "yes"], [

AS_IF([test "$enable_cap_ng" != "no"],[
  PKG_CHECK_MODULES([cap_ng], [cap-ng], [enable_cap_ng=yes], [
    enable_cap_ng=no
    AC_CHECK_HEADER([cap-ng.h], [
      save_LIBS="$LIBS"
      AC_SEARCH_LIBS([capng_apply], [cap-ng], [
        AS_IF([test "$ac_cv_search_capng_apply" != "none required"],
          [cap_ng_LIBS="$ac_cv_search_capng_apply"], [cap_ng_LIBS=])
        AC_SUBST([cap_ng_LIBS])
        enable_cap_ng=yes
      ])
      LIBS="$save_LIBS"
    ])
  ])
], [
  enable_cap_ng=no
  cap_ng_LIBS=
])])

AS_IF([test "$enable_cap_ng" = yes],
  [AC_DEFINE([ENABLE_CAP_NG], [1], [POSIX capabilities available])]
)

save_LIBS="$LIBS"
AC_SEARCH_LIBS([pthread_create], [pthread], [
  AS_IF([test "$ac_cv_search_pthread_create" != "none required"],
    [pthread_LIBS="$ac_cv_search_pthread_create"], [pthread_LIBS=])
  AC_SUBST([pthread_LIBS])
],[
  AC_MSG_ERROR([pthreads not found])
])
LIBS="$save_LIBS"

save_LIBS="$LIBS"
AC_SEARCH_LIBS([dlopen], [dl], [
  AS_IF([test "$ac_cv_search_dlopen" != "none required"],
    [dlopen_LIBS="$ac_cv_search_dlopen"], [dlopen_LIBS=])
  AC_SUBST([dlopen_LIBS])
],[
  AC_MSG_ERROR([dlopen not found])
])
LIBS="$save_LIBS"

save_LIBS="$LIBS"
AC_SEARCH_LIBS([pow], [m], [
  AS_IF([test "$ac_cv_search_pow" != "none required"],
    [math_LIBS="$ac_cv_search_pow"], [math_LIBS=])
  AC_SUBST([math_LIBS])
],[
  AC_MSG_ERROR([math not found])
])
LIBS="$save_LIBS"

save_LIBS="$LIBS"
AC_SEARCH_LIBS([pthread_setaffinity_np], [pthread], [
  AC_DEFINE([HAVE_PTHREAD_SETAFFINITY_NP], [1],
  [Define to 1 if you have the pthread_setaffinity_np function.])
])
LIBS="$save_LIBS"

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS_ONCE([pthread_np.h sys/uio.h bsd/string.h])

# Checks for optional library functions.
AC_CHECK_FUNCS([accept4 clock_gettime fgetln getline initgroups malloc_trim \
                setgroups strlcat strlcpy sysctlbyname])

# Check for robust memory cleanup implementations.
AC_CHECK_FUNC([explicit_bzero], [
  AC_DEFINE([HAVE_EXPLICIT_BZERO], [1], [explicit_bzero available])
  explicit_bzero=yes], [explicit_bzero=no]
)
AC_CHECK_FUNC([explicit_memset], [
  AC_DEFINE([HAVE_EXPLICIT_MEMSET], [1], [explicit_memset available])
  explicit_memset=yes], [explicit_memset=no]
)
AM_CONDITIONAL([USE_GNUTLS_MEMSET], [test "$explicit_bzero" = "no" -a "$explicit_memset" = "no" -a "$gnutls_memset" = "yes"])

# Check for mandatory library functions.
AC_CHECK_FUNC([vasprintf], [], [
  AC_MSG_ERROR([vasprintf support in the libc is required])])

# Check for cpu_set_t/cpuset_t compatibility
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <pthread.h>]], [[cpu_set_t set; CPU_ZERO(&set);]])],
[AC_DEFINE(HAVE_CPUSET_LINUX, 1, [Define if Linux-like cpu_set_t exists.])])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <pthread_np.h>]], [[cpuset_t set; CPU_ZERO(&set);]])],
[AC_DEFINE(HAVE_CPUSET_BSD, 1, [Define if FreeBSD-like cpuset_t exists.])])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <sched.h>]], [[cpuset_t* set = cpuset_create(); cpuset_destroy(set);]])],
[AC_DEFINE(HAVE_CPUSET_NETBSD, 1, [Define if cpuset_t and cpuset(3) exists.])])

# Check for '__atomic' compiler builtin atomic functions.
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([[#include <stdint.h>]],
                   [[uint64_t val = 0; __atomic_add_fetch(&val, 1, __ATOMIC_RELAXED);]])],
  [AC_DEFINE(HAVE_ATOMIC, 1, [Define to 1 if you have '__atomic' functions.])]
)

# Check for '__sync' compiler builtin atomic functions.
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([[#include <stdint.h>]],
                   [[int val = 0; __sync_add_and_fetch(&val, 1);]])],
  [AC_DEFINE(HAVE_SYNC_ATOMIC, 1, [Define to 1 if you have '__sync' functions.])]
)

# Prepare CFLAG_VISIBILITY to be used where needed
gl_VISIBILITY()

# Add code coverage macro
AX_CODE_COVERAGE

AX_SANITIZER
AS_IF([test -n "$sanitizer_CFLAGS"], [CFLAGS="$CFLAGS $sanitizer_CFLAGS"])
AM_CONDITIONAL([FUZZER], [test "$with_fuzzer" != "no"])
AM_CONDITIONAL([OSS_FUZZ], [test "$with_oss_fuzz" != "no"])

AS_IF([test "$enable_documentation" = "yes"],[

AC_PATH_PROGS([SPHINXBUILD], [sphinx-build sphinx-build-3], [false])
AS_IF([test "$SPHINXBUILD" = "false"],
  [AC_MSG_WARN([Could not find the 'sphinx-build' executable, you will be unable to regenerate documentation.])],
  [AC_PATH_PROG([PDFLATEX], [pdflatex], [false])
   AS_IF([test "$PDFLATEX" = ""],
     [AC_MSG_WARN([Could not find the 'pdflatex' executable, you will be unable to generate PDF documentation.])])
   AC_PATH_PROG([MAKEINFO], [makeinfo], [false])
   AS_IF([test "$MAKEINFO" = "false"],
     [AC_MSG_WARN([Could not find the 'makeinfo' executable, you will be unable to generate info documentation.])])
  ])

])

AM_CONDITIONAL([HAVE_SPHINXBUILD], test "$SPHINXBUILD" != "false")
AM_CONDITIONAL([HAVE_PDFLATEX], test "$PDFLATEX" != "false")
AM_CONDITIONAL([HAVE_MAKEINFO], test "$MAKEINFO" != "false")

# Strip -fdebug-prefix-map= parameters from flags for better reproducibility of binaries.
filtered_cflags=$(echo -n "$CFLAGS" | \
                  sed 's/[[^[:alnum:]]]-f[[^[:space:]]]*-prefix-map=[[^[:space:]]]*//g')
filtered_cppflags=$(echo -n "$CPPFLAGS" | \
                    sed 's/[[^[:alnum:]]]-f[[^[:space:]]]*-prefix-map=[[^[:space:]]]*//g')

result_msg_base="  Knot DNS $VERSION

    Target:   $host_os $host_cpu $endianity
    Compiler: ${CC}
    CFLAGS:   ${filtered_cflags} ${filtered_cppflags}
    LIBS:     ${LIBS} ${LDFLAGS}
    LibURCU:  ${liburcu_LIBS} ${liburcu_CFLAGS}
    GnuTLS:   ${gnutls_LIBS} ${gnutls_CFLAGS}
    Libedit:  ${libedit_LIBS} ${libedit_CFLAGS}
    LMDB:     ${lmdb_LIBS} ${lmdb_CFLAGS}
    Config:   ${conf_mapsize} MiB default mapsize

    Prefix:      ${knot_prefix}
    Run dir:     ${run_dir}
    Storage dir: ${storage_dir}
    Config dir:  ${config_dir}
    Module dir:  ${module_dir}

    Static modules: ${static_modules}
    Shared modules: ${shared_modules}

    Knot DNS libraries:     yes
    Knot DNS daemon:        ${enable_daemon}
    Knot DNS utilities:     ${enable_utilities}
    Knot DNS documentation: ${enable_documentation}

    Use recvmmsg:           ${enable_recvmmsg}
    Use SO_REUSEPORT(_LB):  ${enable_reuseport}
    XDP support:            ${enable_xdp}
    Ngtcp2 (DoQ):           ${with_libngtcp2}
    Socket polling:         ${socket_polling}
    Memory allocator:       ${with_memory_allocator}
    Fast zone parser:       ${enable_fastparser}
    Utilities with IDN:     ${with_libidn}
    Utilities with DoH:     ${with_libnghttp2}
    Utilities with Dnstap:  ${enable_dnstap}
    MaxMind DB support:     ${enable_maxminddb}
    Systemd integration:    ${enable_systemd}
    POSIX capabilities:     ${enable_cap_ng}
    PKCS #11 support:       ${enable_pkcs11}
    Ed25519 support:        ${enable_ed25519}
    Ed448 support:          ${enable_ed448}
    Reproducible signing:   ${enable_repro_signing}
    Code coverage:          ${enable_code_coverage}
    Sanitizer:              ${with_sanitizer}
    LibFuzzer:              ${with_fuzzer}
    OSS-Fuzz:               ${with_oss_fuzz}"

result_msg_esc=$(echo -n "$result_msg_base" | sed '$!s/$/\\n/' | tr -d '\n')

AC_DEFINE_UNQUOTED([CONFIGURE_SUMMARY],["$result_msg_esc"],[Configure summary])

AC_CONFIG_FILES([Makefile
                 Doxyfile
                 doc/Makefile
                 tests/Makefile
                 tests-fuzz/Makefile
                 samples/Makefile
                 distro/Makefile
                 python/Makefile
                 python/setup.py
                 python/libknot/__init__.py
                 src/Makefile
                 src/libknot/xdp/Makefile
                 src/knot/modules/static_modules.h
                 ])

AC_CONFIG_FILES([doc/modules.rst],
                [cp doc/modules.rst "${srcdir}"/doc/modules.rst 2>/dev/null
                 abs_srcdir=$(cd "${srcdir}" && pwd)
                 ln -s -f "${abs_srcdir}"/src/knot/modules "${srcdir}"/doc 2>/dev/null])

AC_OUTPUT
AC_MSG_RESULT([
$result_msg_base
])
