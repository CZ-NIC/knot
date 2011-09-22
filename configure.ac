#                                               -*- Autoconf -*-

AC_PREREQ([2.65])
AC_INIT([knot], [0.3], [bug-me-knot@nic.cz])
AM_INIT_AUTOMAKE([gnu -Wall -Werror])
AC_CONFIG_SRCDIR([src/knot/main.c])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS([_GNU_SOURCE])
AX_EXT

# Enable maintainer mode by default for development
AM_MAINTAINER_MODE([enable])

# Initialize libtool
LT_INIT

# Checks for programs.
AC_PROG_CC
AM_PROG_LEX

AC_CACHE_CHECK([for reentrant lex], [ac_cv_path_LEX_R],
  [AC_PATH_PROGS_FEATURE_CHECK([LEX_R], [$LEX flex gflex],
    [[$ac_path_LEX_R -t>/dev/null 2>/dev/null<<END && ac_cv_path_LEX_R=$ac_path_LEX_R ac_path_LEX_R_found=true
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
END
    ]],
    [AC_MSG_ERROR([could not find lex that supports reentrant parsers])])])
AC_SUBST([LEX], [$ac_cv_path_LEX_R])

AC_PROG_YACC
YACC_BISON=`bison --version | awk '{print $1;exit}'`
if test "$YACC_BISON" != "bison"; then
    AC_MSG_ERROR([GNU bison needed for reentrant parsers, set the \$YACC variable before running configure])
fi
AC_PROG_INSTALL

# Set compiler compatibility flags
AC_PROG_CPP_WERROR
AC_PROG_CC_C99

AC_ARG_ENABLE([ldns],
     AC_HELP_STRING([--enable-ldns=yes|no], [Enable tests with ldns [default=no]]),
     [case "${enableval}" in
       yes) AC_SEARCH_LIBS([ldns_rr_list_pop_rrset], [ldns], [AC_DEFINE([HAVE_LDNS], [1], [ldns present])],
       AC_MSG_ERROR([ldns not found])) ;;
       no)  ldns=false ;;
       *) AC_MSG_ERROR([bad value ${enableval} for --enable-ldns]) ;;
     esac],[ldns=false])

# Debug level
AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug=brief|verbose|details], [enable given debug level [default=disabled]]),
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

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lm':
# TODO: check if paths exist before appending
CFLAGS="$CFLAGS -I/usr/local/include"
LDFLAGS="$LDFLAGS -L/usr/local/lib"
AC_SEARCH_LIBS([pow], [m])
AC_SEARCH_LIBS([pthread_create], [pthread], [], [AC_MSG_ERROR([pthreads not found])])
AC_SEARCH_LIBS([rcu_set_pointer_sym], [urcu], [], [AC_MSG_ERROR([liburcu not found])])
#AC_SEARCH_LIBS([clock_gettime], [rt], [], [AC_MSG_ERROR([librt not found])])
AC_SEARCH_LIBS([OpenSSL_add_all_digests], [crypto],[], [AC_MSG_ERROR([libcrypto not found])])
AC_SEARCH_LIBS([ev_loop_new], [ev],[], [AC_MSG_ERROR([libev not found])])
#AC_SEARCH_LIBS([ldns_rr_list_pop_rrset], [ldns], [], [AC_MSG_ERROR([libldns not found])])

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h malloc.h netdb.h netinet/in.h stdint.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h urcu.h ev.h])

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

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MMAP
AC_CHECK_FUNCS([gethostbyname gettimeofday memmove memset munmap regcomp select socket sqrt strcasecmp strchr strdup strerror strncasecmp strtol strtoul poll epoll_wait kqueue])

AC_CONFIG_FILES([Makefile
                 libknot/Makefile
		 samples/Makefile
                 src/Makefile])
AC_OUTPUT
