#                                               -*- Autoconf -*-

AC_PREREQ([2.60])
AC_INIT([knot], [1.3.0-rc5], [knot-dns@labs.nic.cz])
AM_INIT_AUTOMAKE([gnits subdir-objects dist-bzip2 dist-xz -Wall -Werror])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([src/knot/main.c])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS([_GNU_SOURCE])

# Automatically update release date based on configure.ac date
release_date=`doc/mdate-sh configure.ac`
AC_SUBST([RELEASE_DATE], $release_date)

# Check SSE, SSE2 and SSE3 support
AX_EXT
CFLAGS="$CFLAGS $SIMD_FLAGS"

# Set compiler compatibility flags
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_CPP_WERROR

# Checks for programs.
m4_ifdef([AM_PROG_AR], [AM_PROG_AR]) # call AM_PROG_AR only if available

# Initialize libtool
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
LT_INIT

# Use pkg-config
PKG_PROG_PKG_CONFIG

AC_CACHE_CHECK([for reentrant lex], [ac_cv_path_LEX],
  [AC_PATH_PROGS_FEATURE_CHECK([LEX], [$LEX flex gflex],
  [cat >conftest.l <<_ACEOF
%{
%}

%option reentrant
%option bison-bridge
%option noinput
%option nounput
%option noreject

BLANK [ \t\n]

%%
<<EOF>> return 0;
%%
_ACEOF
_AC_DO_VAR(ac_path_LEX conftest.l)
test $ac_status -eq 0 && ac_cv_path_LEX=$ac_path_LEX ac_path_LEX_found=true
rm -f conftest.l lexyy.c lex.yy.c
],
[AC_MSG_ERROR([could not find lex that supports reentrant parsers])])])
AC_SUBST([LEX], [$ac_cv_path_LEX])
AM_PROG_LEX

AC_PROG_YACC
YACC_BISON=`bison --version | awk '{print $1;exit}'`
AS_IF([test "x$YACC_BISON" != "xbison"],
    [AC_MSG_ERROR([GNU bison needed for reentrant parsers, set the \$YACC variable before running configure])])
AC_PROG_INSTALL

# Check for Ragel
AC_PATH_PROG([RAGEL], [ragel], [true])
AM_CONDITIONAL([HAVE_RAGEL], test "$RAGEL" != "true")

# Set FSM type for Ragel
AC_SUBST([FSM_TYPE], [-T0])
AC_ARG_ENABLE([fastparser],
    AS_HELP_STRING([--enable-fastparser], [Generate fast zone parser (requires Ragel!)]),
    [touch src/zscanner/scanner.rl; AC_SUBST([FSM_TYPE], [-G2])],
    [])

# Debug modules
AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug=server,zones,xfr,packet,dname,rr,ns,hash,compiler,stash],
    [compile selected debug modules [default=none]]),
    [
    echo ${enableval}|tr "," "\n"|while read val; do
        case "${val}" in
          server) AC_DEFINE([KNOTD_SERVER_DEBUG], [1], [Server debug.]) ;;
          zones) AC_DEFINE([KNOT_ZONES_DEBUG], [1], [Zones debug.]) ;;
          xfr) AC_DEFINE([KNOT_XFR_DEBUG], [1], [XFR debug.]) ;;
          packet) AC_DEFINE([KNOT_PACKET_DEBUG], [1], [Packet debug.]) ;;
          dname) AC_DEFINE([KNOT_DNAME_DEBUG], [1], [Domain names debug.]) ;;
          rr) AC_DEFINE([KNOT_RR_DEBUG], [1], [RR debug.]) ;;
          ns) AC_DEFINE([KNOT_NS_DEBUG], [1], [Nameserver debug.]) ;;
          hash) AC_DEFINE([KNOT_HASH_DEBUG], [1], [Hashtable debug.]) ;;
          compiler) AC_DEFINE([KNOT_COMPILER_DEBUG], [1], [Zone compiler debug.]) ;;
          stash) AC_DEFINE([KNOT_STASH_DEBUG], [1], [Hash table stash debug.]) ;;
        esac
    done
    ], [])

# Debug level
AC_ARG_ENABLE([debuglevel],
    AS_HELP_STRING([--enable-debuglevel=brief|verbose|details], [enable given debug level [default=disabled]]),
    # Not all shells support fall-through with ;& so I have to duplicate
    [case "x${enableval}" in
      xdetails)
        AC_DEFINE([DEBUG_ENABLE_DETAILS], [1], [Enable details debugging messages.])
        AC_DEFINE([DEBUG_ENABLE_VERBOSE], [1], [Enable verbose debugging messages.])
        AC_DEFINE([DEBUG_ENABLE_BRIEF], [1], [Enable brief debugging messages.])
        ;;
      xverbose)
        AC_DEFINE([DEBUG_ENABLE_VERBOSE], [1], [Enable verbose debugging messages.])
        AC_DEFINE([DEBUG_ENABLE_BRIEF], [1], [Enable brief debugging messages.])
        ;;
      xbrief)
        AC_DEFINE([DEBUG_ENABLE_BRIEF], [1], [Enable brief debugging messages.])
        ;;
    esac], [])

# recvmmsg() (valgrind doesn't support it, so disable for debugging)
# The check for struct mmsghdr is required when libc doesn't have an API but the function links
AC_ARG_ENABLE([recvmmsg],
    AS_HELP_STRING([--enable-recvmmsg=yes|no], [enable recvmmsg() network API under Linux (kernel support required) (set to 'no' if you have trouble running server under valgrind) [default=yes]]),
    [case "${enableval}" in
      yes)
	  AC_CHECK_FUNCS([sendmmsg])
          AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <sys/socket.h>]], [[struct mmsghdr v; recvmmsg(0,0,0,0,0);]])],
          [AC_DEFINE(HAVE_RECVMMSG, 1, [Define if struct mmsghdr and recvmmsg() exists.])])
          ;;
      no)
          ;;
      *)
          AC_MSG_ERROR([bad value ${enableval} for --enable-recvmmsg])
          ;;
    esac],
    [
      AC_CHECK_FUNCS([sendmmsg])
      AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <sys/socket.h>]], [[struct mmsghdr v; recvmmsg(0,0,0,0,0);]])],
      [AC_DEFINE(HAVE_RECVMMSG, 1, [Define if struct mmsghdr and recvmmsg() exists.])])
    ])

# Enable integrity check
AC_ARG_ENABLE([integrity-check],
    AS_HELP_STRING([--enable-integrity-check], [enable integrity check in knotd via SIGUSR1]),
    [AC_DEFINE([INTEGRITY_CHECK], [1], [integrity check in knotd])])

# Check for link time optimizations support and predictive commoning
AC_ARG_ENABLE([lto],
    AS_HELP_STRING([--enable-lto=yes|no], [enable link-time optimizations, enable if not broken for some extra speed [default=no]]),
    [case "${enableval}" in
      yes) AX_CHECK_COMPILE_FLAG("-flto", [CFLAGS="$CFLAGS -flto"], []) ;;
      no) ;;
      *)  AC_MSG_ERROR([bad value ${enableval} for --enable-lto]) ;;
    esac])

# Check for enable microseconds in log messages
AC_ARG_ENABLE([microseconds-log],
    AS_HELP_STRING([--enable-microseconds-log], [enable microseconds in log messages [default=no]]),
    AC_DEFINE([ENABLE_MICROSECONDS_LOG], [1], [microseconds in log messages]))

AX_CHECK_COMPILE_FLAG("-fpredictive-commoning", [CFLAGS="$CFLAGS -fpredictive-commoning"], [], "-Werror")

# Disable strict aliasing
# FIXME: we break strict aliasing on many occurenes, disable it until resolved or kept
AX_CHECK_COMPILE_FLAG("-fno-strict-aliasing", [CFLAGS="$CFLAGS -fno-strict-aliasing"], [])

# Default directories
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

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lm':

dnl Check for userspace-rcu library
AC_ARG_WITH(urcu,
[  --with-urcu=DIR        where to find userspace-rcu library])

AS_IF([test "$with_urcu" != "no"], [
  PKG_CHECK_MODULES([liburcu], liburcu, [
    CPPFLAGS="$CPPFLAGS $liburcu_CFLAGS"
    LIBS="$LIBS $liburcu_LIBS"
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
	break
      ],[
        CPPFLAGS="$save_CPPFLAGS"
        LIBS="$save_LIBS"
        with_urcu=no
	# do not cache result of AC_SEARCH_LIBS test
	unset ac_cv_search_rcu_set_pointer_sym
      ])
    done

    AS_IF([test "$with_urcu" = "no"],[
      AC_MSG_ERROR([liburcu is required])
    ])
  ])
])

AC_SEARCH_LIBS([urcu_init], [urcu], [AC_MSG_ERROR([liburcu is too old (< 0.4.0), urcu_init symbol found])], [])

dnl Check for OpenSSL
AC_ARG_WITH(openssl,
[  --with-openssl=DIR        where to find openssl library])

AS_IF([test "$with_openssl" != "no"],[
  PKG_CHECK_MODULES([libcrypto], libcrypto, [
    CPPFLAGS="$CPPFLAGS $libcrypto_CFLAGS"
    LIBS="$LIBS $libcrypto_LIBS"
    with_openssl=yes
  ],[

    for try_openssl in "$with_openssl" "" "/usr/local"; do
      save_LIBS="$LIBS"
      save_CPPFLAGS="$CPPFLAGS"

      AS_IF([test -d "$try_openssl"], [
        libcrypto_CFLAGS="-I$try_openssl/include"
        libcrypto_LIBS="-L$try_openssl/lib"
      ],[
        libcrypto_CFLAGS=""
        libcrypto_LIBS=""
      ])

      CPPFLAGS="$CPPFLAGS $libcrypto_CFLAGS"
      LIBS="$LIBS $libcrypto_LIBS"

      AC_SEARCH_LIBS([OpenSSL_add_all_digests], [crypto], [
        with_openssl=yes
	break
      ],[
        with_openssl=no
	# do not cache result of AC_SEARCH_LIBS test
	unset ac_cv_search_OpenSSL_add_all_digests
      ])

      CPPFLAGS="$save_CPPFLAGS"
      LIBS="$save_LIBS"
    done

    AS_IF([test "$with_openssl" = "no"],[
      AC_MSG_ERROR([libcrypto (part of OpenSSL) is required])
    ])
  ])
])

AC_SEARCH_LIBS([pow], [m])
AC_SEARCH_LIBS([pthread_create], [pthread], [], [AC_MSG_ERROR([pthreads not found])])
AC_SEARCH_LIBS([dlopen], [dl])
AC_SEARCH_LIBS([clock_gettime], [rt])
AC_SEARCH_LIBS([capng_apply], [cap-ng])
AC_SEARCH_LIBS([adler32], [z])

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS_ONCE([cap-ng.h netinet/in_systm.h pthread_np.h signal.h sys/select.h sys/time.h sys/wait.h sys/uio.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Set PRNG parameters
AC_DEFINE([DSFMT_MEXP], [521], [DSFMT parameters])

# Checks for library functions.
AC_CHECK_FUNCS([clock_gettime gettimeofday fgetln getline madvise poll posix_memalign pselect pthread_setaffinity_np regcomp select setgroups])

# Check for cpu_set_t/cpuset_t compatibility
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <pthread.h>]], [[cpu_set_t set; CPU_ZERO(&set);]])],
[AC_DEFINE(HAVE_CPUSET_LINUX, 1, [Define if Linux-like cpu_set_t exists.])])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <pthread_np.h>]], [[cpuset_t set; CPU_ZERO(&set);]])],
[AC_DEFINE(HAVE_CPUSET_BSD, 1, [Define if FreeBSD-like cpuset_t exists.])])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <sched.h>]], [[cpuset_t* set = cpuset_create(); cpuset_destroy(set);]])],
[AC_DEFINE(HAVE_CPUSET_NETBSD, 1, [Define if cpuset_t and cpuset(3) exists.])])

gl_VISIBILITY()
CFLAGS="$CFLAGS $CFLAG_VISIBILITY"

AC_CONFIG_FILES([Makefile
		 samples/Makefile
		 src/Makefile
		 src/tests/Makefile
		 doc/Makefile
		 man/Makefile
		 src/zscanner/test/run_tests.sh
		 src/zscanner/test/cases/06-3_INCLUDE.in:src/zscanner/test/cases/06-3_INCLUDE.inin
		 src/zscanner/test/cases/06-4_INCLUDE.in:src/zscanner/test/cases/06-4_INCLUDE.inin
		 src/zscanner/test/cases/06-0_INCLUDE.in:src/zscanner/test/cases/06-0_INCLUDE.inin
		 man/khost.1
		 man/knotc.8
		 man/knotd.8
		 man/kdig.1
		 man/knsupdate.1
		 man/knot.conf.5
		 ])
AC_OUTPUT
