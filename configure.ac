#                                               -*- Autoconf -*-

AC_PREREQ([2.65])
AC_INIT([knot], [0.2], [bug-me-knot@nic.cz])
AM_INIT_AUTOMAKE([gnu -Wall -Werror silent-rules])
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
AC_CHECK_LIB([m], [pow])
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([urcu], [rcu_read_lock])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([crypto], [OpenSSL_add_all_digests])
#AC_CHECK_LIB([ldns], [ldns_rr_list_pop_rrset])

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h malloc.h netdb.h netinet/in.h stdint.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h])

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
