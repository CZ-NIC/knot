#                                               -*- Autoconf -*-

AC_PREREQ([2.60])
AC_INIT([knot], [1.1.3], [knot-dns@labs.nic.cz])
AM_INIT_AUTOMAKE([gnu -Wall -Werror])
AC_CONFIG_SRCDIR([src/knot/main.c])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS([_GNU_SOURCE])
AX_EXT

# Checks for programs.
AC_PROG_CC
m4_pattern_allow([AM_PROG_AR]) # for automake 1.12
AM_PROG_AR

# Initialize libtool
AC_PROG_LIBTOOL
LT_INIT

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

# Set compiler compatibility flags
AC_PROG_CPP_WERROR
AC_PROG_CC_C99

AC_ARG_ENABLE([ldns],
     AS_HELP_STRING([--enable-ldns=yes|no], [Enable tests with ldns [default=no]]),
     [case "${enableval}" in
       yes) AC_SEARCH_LIBS([ldns_rr_list_pop_rrset], [ldns], [AC_DEFINE([HAVE_LDNS], [1], [ldns present])],
       AC_MSG_ERROR([ldns not found])) ;;
       no)  ldns=false ;;
       *) AC_MSG_ERROR([bad value ${enableval} for --enable-ldns]) ;;
     esac],[ldns=false])
     
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
AC_ARG_ENABLE([recvmmsg],
    AS_HELP_STRING([--enable-recvmmsg=yes|no], [enable recvmmsg() network API under Linux (kernel support required) (set to 'no' if you have trouble running server under valgrind) [default=yes]]),
    [case "${enableval}" in
      yes)
         AC_DEFINE([ENABLE_RECVMMSG], [1], [recvmmsg enabled])
         ;;
      no)
         recvmmsg=false
         ;;
      *) 
         AC_MSG_ERROR([bad value ${enableval} for --enable-recvmmsg])
         ;;
    esac], [
    AC_DEFINE([ENABLE_RECVMMSG], [1], [recvmmsg enabled])
    recvmmsg=true
    ])

# Check for link time optimizations support and predictive commoning
AC_ARG_ENABLE([lto],
    AS_HELP_STRING([--enable-lto=yes|no], [enable link-time optimizations, enable if not broken for some extra speed [default=no]]),
    [case "${enableval}" in
      yes) AX_CHECK_COMPILER_FLAGS("-flto", [CFLAGS="$CFLAGS -flto"], []) ;;
      no) ;;
      *)  AC_MSG_ERROR([bad value ${enableval} for --enable-lto]) ;;
    esac], [
    ])

AX_CHECK_COMPILER_FLAGS("-fpredictive-commoning", [CFLAGS="$CFLAGS -fpredictive-commoning"], [])

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lm':
# TODO: check if paths exist before appending
CFLAGS="$CFLAGS -I/usr/local/include $SIMD_FLAGS"
LDFLAGS="$LDFLAGS -L/usr/local/lib"
AC_SEARCH_LIBS([pow], [m])
AC_SEARCH_LIBS([pthread_create], [pthread], [], [AC_MSG_ERROR([pthreads not found])])
AC_SEARCH_LIBS([rcu_set_pointer_sym], [urcu], [], [AC_MSG_ERROR([liburcu not found])])
AC_SEARCH_LIBS([urcu_init], [urcu], [AC_MSG_ERROR([liburcu is too old (< 0.4.0), urcu_init symbol found])], [])
AC_SEARCH_LIBS([dlopen], [dl])
AC_SEARCH_LIBS([clock_gettime], [rt])
AC_SEARCH_LIBS([OpenSSL_add_all_digests], [crypto],[], [AC_MSG_ERROR([libcrypto not found])])
AC_SEARCH_LIBS([capng_apply], [cap-ng])
AC_SEARCH_LIBS([adler32], [z])
#AC_SEARCH_LIBS([ldns_rr_list_pop_rrset], [ldns], [], [AC_MSG_ERROR([libldns not found])])

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h malloc.h netdb.h netinet/in_systm.h netinet/in.h stdint.h stdlib.h string.h strings.h sys/socket.h sys/time.h cap-ng.h syslog.h unistd.h urcu.h ev.h pthread_np.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Set PRNG parameters
AC_DEFINE([DSFMT_MEXP], [521], [DSFMT parameters.])

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MMAP
AC_CHECK_FUNCS([gethostbyname gettimeofday clock_gettime memalign memmove memset munmap regcomp pselect select socket sqrt strcasecmp strchr strdup strerror strncasecmp strtol strtoul poll epoll_wait kqueue setgroups sendmmsg madvise pthread_setaffinity_np])

# Check for cpu_set_t/cpuset_t compatibility
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <pthread.h>]], [[cpu_set_t set; CPU_ZERO(&set);]])],
[AC_DEFINE(HAVE_CPUSET_LINUX, 1, [Define if Linux-like cpu_set_t exists.])])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <pthread_np.h>]], [[cpuset_t set; CPU_ZERO(&set);]])],
[AC_DEFINE(HAVE_CPUSET_BSD, 1, [Define if FreeBSD-like cpuset_t exists.])])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <sched.h>]], [[cpuset_t* set = cpuset_create(); cpuset_destroy(set);]])],
[AC_DEFINE(HAVE_CPUSET_NETBSD, 1, [Define if cpuset_t and cpuset(3) exists.])])

AC_CONFIG_FILES([Makefile
		 samples/Makefile
                 src/Makefile
		 doc/Makefile])
AC_OUTPUT
