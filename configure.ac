#                                               -*- Autoconf -*-

AC_PREREQ([2.65])
AC_INIT([knot], [0.2], [bug-me-knot@nic.cz])
AM_INIT_AUTOMAKE([gnu -Wall -Werror])
AC_CONFIG_SRCDIR([src/knot/main.c])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS([_GNU_SOURCE])

# Enable maintainer mode by default for development
AM_MAINTAINER_MODE([enable])

# Initialize libtool
LT_INIT

# Checks for programs.
AC_PROG_CC
AC_PROG_LEX
AC_PROG_YACC
AC_PROG_INSTALL

# Set compiler compatibility flags
AC_PROG_CPP_WERROR
AC_PROG_CC_C99

AC_ARG_ENABLE([ldns],
     [  --enable-ldns    Enable tests with ldns],
     [case "${enableval}" in
       yes) AC_CHECK_LIB([ldns], [ldns_rr_list_pop_rrset]) ;;
       no)  ldns=false ;;
       *) AC_MSG_ERROR([bad value ${enableval} for --enable-ldns]) ;;
     esac],[ldns=false])

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lm':
# TODO: check if paths exist before appending
CFLAGS="$CFLAGS -I/usr/local/include"
LDFLAGS="$LDFLAGS -L/usr/local/lib"
AC_SEARCH_LIBS([pow], [m])
AC_SEARCH_LIBS([pthread_create], [pthread], [], [AC_MSG_ERROR([pthreads not found])])
AC_SEARCH_LIBS([rcu_read_lock], [urcu], [], [AC_MSG_ERROR([liburcu not found])])
#AC_SEARCH_LIBS([clock_gettime], [rt], [], [AC_MSG_ERROR([librt not found])])
AC_SEARCH_LIBS([OpenSSL_add_all_digests], [crypto],[], [AC_MSG_ERROR([libcrypto not found])])
AC_SEARCH_LIBS([ev_run], [ev],[], [AC_MSG_ERROR([libev not found])])
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
AC_CHECK_FUNCS([gethostbyname gettimeofday memmove memset munmap regcomp select socket sqrt strcasecmp strchr strdup strerror strncasecmp strtol strtoul])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
