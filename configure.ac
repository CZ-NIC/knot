AC_PREREQ([2.60])

m4_define([knot_VERSION_MAJOR], 2)dnl
m4_define([knot_VERSION_MINOR], 8)dnl
m4_define([knot_VERSION_PATCH], )dnl Leave empty if the master branch!
m4_include([m4/knot-version.m4])

AC_INIT([knot], knot_PKG_VERSION, [knot-dns@labs.nic.cz])

# Store ./configure parameters and CFLAGS
AC_DEFINE_UNQUOTED([CONFIGURE_PARAMS],["$*"],[Params passed to configure])
AC_DEFINE_UNQUOTED([CONFIGURE_CFLAGS],["$CFLAGS"],[Passed CFLAGS from environment])

AM_INIT_AUTOMAKE([foreign std-options subdir-objects no-dist-gzip dist-xz -Wall -Werror])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([src/knot])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_HOST

# Update library versions
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
AC_SUBST([libknot_VERSION_INFO],["-version-info 8:0:0"])
AC_SUBST([libdnssec_VERSION_INFO],["-version-info 6:0:0"])
AC_SUBST([libzscanner_VERSION_INFO],["-version-info 2:0:0"])

AC_SUBST([KNOT_VERSION_MAJOR], knot_VERSION_MAJOR)
AC_SUBST([KNOT_VERSION_MINOR], knot_VERSION_MINOR)
AC_SUBST([KNOT_VERSION_PATCH], knot_VERSION_PATCH)

AC_CONFIG_FILES([src/libknot/version.h
                 src/libdnssec/version.h
                 src/libzscanner/version.h])

# Automatically update release date based on NEWS
AC_PROG_SED
release_date=$($SED -n 's/^Knot DNS .* (\(.*\))/\1/p;q;' ${srcdir}/NEWS)
AC_SUBST([RELEASE_DATE], $release_date)

# Set compiler compatibility flags
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_CPP_WERROR

# Set default CFLAGS
CFLAGS="$CFLAGS -Wall -Werror=format-security -Werror=implicit -Wstrict-prototypes"

AX_CHECK_COMPILE_FLAG("-fpredictive-commoning", [CFLAGS="$CFLAGS -fpredictive-commoning"], [], "-Werror")
AX_CHECK_LINK_FLAG(["-Wl,--exclude-libs,ALL"], [ldflag_exclude_libs="-Wl,--exclude-libs,ALL"], [ldflag_exclude_libs=""], "")
AC_SUBST([LDFLAG_EXCLUDE_LIBS], $ldflag_exclude_libs)

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
        AC_HELP_STRING([--with-rundir=path], [Path to run-time variable data (pid, sockets...). [default=LOCALSTATEDIR/run/knot]]),
        [run_dir=$withval])
AC_SUBST(run_dir)

storage_dir="${localstatedir}/lib/knot"
AC_ARG_WITH([storage],
        AC_HELP_STRING([--with-storage=path], [Default storage directory (slave zones, persistent data). [default=LOCALSTATEDIR/lib/knot]]),
        [storage_dir=$withval])
AC_SUBST(storage_dir)

config_dir="${sysconfdir}/knot"
AC_ARG_WITH([configdir],
        AC_HELP_STRING([--with-configdir=path], [Default directory for configuration. [default=SYSCONFDIR/knot]]),
        [config_dir=$withval])
AC_SUBST(config_dir)

module_dir=
module_instdir="${libdir}/knot/modules-${KNOT_VERSION_MAJOR}.${KNOT_VERSION_MINOR}"
AC_ARG_WITH([moduledir],
        AC_HELP_STRING([--with-moduledir=path], [Path to auto-loaded dynamic modules. [default not set]]),
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
    AS_HELP_STRING([--disable-fastparser], [Disable use of fastest zone parser]),[],[
    # Set zone parser type - fastest on release build, slowest on dev build
    AS_IF([test -d ".git" -o "$PATCH_VERSION" = "dev"],[
        enable_fastparser=no
        ],[
        enable_fastparser=yes
        ])
    ])

AX_CC_CLANG
AS_IF([test "$enable_fastparser" = "yes"],[
    AS_IF([test -n "$CC_CLANG_VERSION"],[
      enable_fastparser=no
      AC_MSG_WARN([Fast zone parser disabled due to possible compiler bug.])
      AC_MSG_WARN([See https://llvm.org/bugs/show_bug.cgi?id=23490 for details.])
      AC_MSG_WARN([Use --enable-fastparser=force if your know your clang is fixed.])
    ])
])

AS_IF([test "$enable_fastparser" = "force"],[enable_fastparser=yes])

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

    AC_CHECK_DECL([GNUTLS_PK_GOST_01],
        [AC_DEFINE([HAVE_GOST], [1], [GnuTLS GOST support available])
         enable_gost=yes],
        [enable_gost=no],
        [#include <gnutls/gnutls.h>])

    AC_CHECK_FUNC([gnutls_privkey_sign_data2],
        [AC_DEFINE([HAVE_SIGN_DATA2], [1], [gnutls_privkey_sign_data2 available])])

    CFLAGS=$save_CFLAGS
    LIBS=$save_LIBS
])

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

AC_ARG_ENABLE([reuseport],
    AS_HELP_STRING([--enable-reuseport=auto|yes|no], [enable Linux SO_REUSEPORT support [default=auto]]),
    [enable_reuseport="$enableval"], [enable_reuseport=auto])

AC_DEFUN([CHECK_REUSEPORT], [
  AC_CHECK_DECL(
    [SO_REUSEPORT],
    [$1],
    [$2],
    [
    #include <sys/socket.h>
    ]
  )])

AS_IF([test "$enable_reuseport" != no], [
  AS_CASE([$enable_reuseport],
    [auto],[
      AS_CASE([$host_os],
        [linux*], [CHECK_REUSEPORT([enable_reuseport=yes], [enable_reuseport=no])],
        [*], [enable_reuseport=no]
      )],
    [yes],[
      AS_CASE([$host_os],
        [linux*], [CHECK_REUSEPORT([enable_reuseport=yes], [AC_MSG_ERROR([SO_REUSEPORT support not detected.])])],
        [*], [AC_MSG_ERROR(["SO_REUSEPORT not supported on $host_os."])]
      )],
    [*], [AC_MSG_ERROR([Invalid value of --enable-reuseport.])]
  )])

AS_IF([test "$enable_reuseport" = yes],[
   AC_DEFINE([ENABLE_REUSEPORT], [1], [Use SO_REUSEPORT.])])

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
  AC_DEFINE([ENABLE_SYSTEMD], [1], [Use systemd integration.])])

]) dnl enable_daemon

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

dnl Check for LMDB
lmdb_MIN_VERSION_MAJOR=0
lmdb_MIN_VERSION_MINOR=9
lmdb_MIN_VERSION_PATCH=15
lmdb_MIN_VERSION_STRING="$lmdb_MIN_VERSION_MAJOR.$lmdb_MIN_VERSION_MINOR.$lmdb_MIN_VERSION_PATCH"
lmdb_MIN_VERSION_FULL="$((($lmdb_MIN_VERSION_MAJOR << 24) | ($lmdb_MIN_VERSION_MINOR << 16) | $lmdb_MIN_VERSION_PATCH))"
AC_ARG_WITH([lmdb],
    AC_HELP_STRING([--with-lmdb=[DIR]], [Link with external LMDB (>= $lmdb_MIN_VERSION_STRING)]),[
    with_lmdb=$withval
    ],[
    with_lmdb=auto
    ])

have_lmdb=no

AS_IF([test "$with_lmdb" != "no"],[
    save_CPPFLAGS=$CPPFLAGS
    save_LIBS=$LIBS

    # Look for lmdb in given path and common locations
    for try_lmdb in "$with_lmdb" "" "/usr/local"; do

      AS_IF([test -d "$try_lmdb"], [
        lmdb_CFLAGS="-I$try_lmdb/include"
        lmdb_LIBS="-L$try_lmdb/lib"
        ],[
        lmdb_CFLAGS=""
        lmdb_LIBS=""
        ])

      CPPFLAGS="$save_CPPFLAGS $lmdb_CFLAGS"
      LIBS="$save_LIBS $lmdb_LIBS"

      AC_SEARCH_LIBS([mdb_env_open], [lmdb], [
          AC_CHECK_HEADERS([lmdb.h], [], [
              AC_MSG_ERROR([lmdb headers not found in `$try_lmdb', is your installation complete?])])
          AC_COMPUTE_INT(lmdb_VERSION_FULL, MDB_VERSION_FULL, [#include <lmdb.h>],
              AC_MSG_ERROR([Unable to determine lmdb version from MDB_VERSION_FULL]))
          AS_IF([test "$lmdb_VERSION_FULL" -ge "$lmdb_MIN_VERSION_FULL"],[
              lmdb_LIBS="$lmdb_LIBS -llmdb"
              have_lmdb=yes],[
              unset lmdb_CFLAGS
              unset lmdb_LIBS
              AC_MSG_WARN([lmdb version 0.9.15 and higher not found, using embedded version])
              ])
          break
          ])

      unset lmdb_CFLAGS
      unset lmdb_LIBS
      # do not cache result of AC_SEARCH_LIBS test
      unset ac_cv_search_mdb_env_open
    done

    CPPFLAGS="$save_CPPFLAGS"
    LIBS="$save_LIBS"

    # fail the configure if we haven't found lmdb library in the system
    AS_IF([test "$with_lmdb" != "auto" -a "$have_lmdb" = "no"],[
        AC_MSG_ERROR([shared lmdb library not found])
        ])
    ])

AS_IF([test "$have_lmdb" != "no"],[
    AC_SUBST([lmdb_LIBS])
    enable_lmdb=shared
    external_lmdb_CFLAGS=$lmdb_CFLAGS
    external_lmdb_LIBS=$lmdb_LIBS
    ],[
    enable_lmdb=embedded
    lmdb_CFLAGS="-I\$(top_srcdir)/src/contrib/lmdb"
    ])
AM_CONDITIONAL([HAVE_LMDB], test "$enable_lmdb" = "shared")
AC_SUBST([lmdb_CFLAGS])
AC_SUBST([external_lmdb_CFLAGS])
AC_SUBST([external_lmdb_LIBS])

# LMDB mapping sizes
conf_mapsize_default=500
AC_ARG_WITH([conf_mapsize],
    AC_HELP_STRING([--with-conf-mapsize=NUM], [Configuration DB mapsize in MiB [default=$conf_mapsize_default]]),
    [conf_mapsize=$withval],[conf_mapsize=$conf_mapsize_default])

AS_CASE([$conf_mapsize],
    [yes],[conf_mapsize=$conf_mapsize_default],
    [no], [AC_MSG_ERROR([conf_mapsize must be a number])],
    [*],  [AS_IF([test $conf_mapsize != $(( $conf_mapsize + 0 ))],
                 [AC_ERROR([conf_mapsize must be an integer number])])])
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
  AC_HELP_STRING([--with-libidn=[DIR]], [Support IDN (needs GNU libidn2 or libidn)]),
  with_libidn=$withval,
  with_libidn=yes
)

AS_IF([test "$enable_utilities" = "yes"], [
  AS_IF([test "$with_libidn" != "no"], [
    PKG_CHECK_MODULES([libidn2], [libidn2 >= 2.0.0], [
      with_libidn=yes
      AC_DEFINE([LIBIDN], [1], [Define to 1 to enable IDN support])
      AC_DEFINE([LIBIDN_HEADER], [<idn2.h>], [Define to proper libidn header])
    ], [
      PKG_CHECK_MODULES([libidn], [libidn >= 0.0.0], [
        with_libidn=yes
        AC_DEFINE([LIBIDN], [1], [Define to 1 to enable IDN support])
        AC_DEFINE([LIBIDN_HEADER], [<idna.h>], [Define to proper libidn header])
      ], [
        with_libidn=no
        AC_MSG_WARN([libidn2 or libidn not found])
      ])
    ])
  ])
]) # Knot DNS utilities dependencies

AS_IF([test "$enable_daemon" = "yes"], [
  PKG_CHECK_MODULES([cap_ng], [cap-ng], [enable_cap_ng=yes], [
    enable_cap_ng=no
    AC_CHECK_HEADER([cap-ng.h], [
      save_LIBS="$LIBS"
      AC_SEARCH_LIBS([capng_apply], [cap-ng], [
        enable_cap_ng=yes
        cap_ng_LIBS="$ac_cv_search_capng_apply"
        AC_SUBST([cap_ng_LIBS])
      ])
      LIBS="$save_LIBS"
    ])
  ])
], [
  enable_cap_ng=no
  cap_ng_LIBS=
])

AS_IF([test "$enable_cap_ng" = yes],
  [AC_DEFINE([ENABLE_CAP_NG], [1], [POSIX capabilities available])]
)

save_LIBS="$LIBS"
AC_SEARCH_LIBS([pthread_create], [pthread], [
  pthread_LIBS="$ac_cv_search_pthread_create"
  AC_SUBST([pthread_LIBS])
],[
  AC_MSG_ERROR([pthreads not found])
])
LIBS="$save_LIBS"

save_LIBS="$LIBS"
AC_SEARCH_LIBS([dlopen], [dl], [
  dlopen_LIBS="$ac_cv_search_dlopen"
  AC_SUBST([dlopen_LIBS])
],[
  AC_MSG_ERROR([dlopen not found])
])
LIBS="$save_LIBS"

AC_SEARCH_LIBS([pow], [m], [], [AC_MSG_ERROR([math not found])])
AC_SEARCH_LIBS([clock_gettime], [rt])

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS_ONCE([pthread_np.h sys/uio.h])

# Checks for optional library functions.
AC_CHECK_FUNCS([accept4 clock_gettime fgetln getline initgroups malloc_trim \
                pthread_setaffinity_np setgroups strlcat strlcpy sysctlbyname])

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

AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([[#include <stdint.h>]],
                   [[uint64_t val = 0; __atomic_add_fetch(&val, 1, __ATOMIC_RELAXED);]])],
  [AC_DEFINE(HAVE_ATOMIC, 1, [Define to 1 if you have '__atomic' functions.])]
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

result_msg_base="  Knot DNS $VERSION

    Target:   $host_os $host_cpu
    Compiler: ${CC}
    CFLAGS:   ${CFLAGS} ${CPPFLAGS}
    LIBS:     ${LIBS} ${LDFLAGS}
    LibURCU:  ${liburcu_LIBS} ${liburcu_CFLAGS}
    GnuTLS:   ${gnutls_LIBS} ${gnutls_CFLAGS}
    Libedit:  ${libedit_LIBS} ${libedit_CFLAGS}
    LMDB:     ${enable_lmdb} ${lmdb_LIBS} ${lmdb_CFLAGS}
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
    Use SO_REUSEPORT:       ${enable_reuseport}
    Memory allocator:       ${with_memory_allocator}
    Fast zone parser:       ${enable_fastparser}
    Utilities with IDN:     ${with_libidn}
    Utilities with Dnstap:  ${enable_dnstap}
    MaxMind DB support:     ${enable_maxminddb}
    Systemd integration:    ${enable_systemd}
    POSIX capabilities      ${enable_cap_ng}
    PKCS #11 support:       ${enable_pkcs11}
    Ed25519 support:        ${enable_ed25519}
    GOST support:           ${enable_gost}
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
                 src/Makefile
                 src/knot/modules/static_modules.h
                 ])

AC_CONFIG_FILES([doc/modules.rst],
                [cp doc/modules.rst ${srcdir}/doc/modules.rst 2>/dev/null;
                 ln -s -f $(readlink -f ${srcdir})/src/knot/modules ${srcdir}/doc 2>/dev/null])

AC_OUTPUT
AC_MSG_RESULT([
$result_msg_base
])
