# Copyright (C) CZ.NIC, z.s.p.o. and contributors
# SPDX-License-Identifier: GPL-2.0-or-later
# For more information, see <https://www.knot-dns.cz/>

AC_DEFUN([AX_CODE_COVERAGE], [
	dnl Check for --enable-code-coverage
	AC_ARG_ENABLE([code-coverage],
		AS_HELP_STRING([--enable-code-coverage], [enable code coverage testing with gcov]),
		[enable_code_coverage=$enableval],
		[enable_code_coverage=no]
	)
	AM_CONDITIONAL([CODE_COVERAGE_ENABLED], [test "$enable_code_coverage" = "yes"])
	AC_SUBST([CODE_COVERAGE_ENABLED], [$enable_code_coverage])

	AS_IF([test "$enable_code_coverage" = "yes"], [
		AC_CHECK_PROG([LCOV], [lcov], [lcov])
		AC_CHECK_PROG([GENHTML], [genhtml], [genhtml])

		AS_IF([test -z "$LCOV"], [
			AC_MSG_ERROR([Could not find lcov])
		])
		AS_IF([test -z "$GENHTML"], [
			AC_MSG_ERROR([Could not find genhtml from the lcov package])
		])
	
		dnl Remove all optimization flags from CFLAGS
		changequote({,})
		CFLAGS=`echo "$CFLAGS" | $SED -e 's/-O[0-9]*//g'`
		changequote([,])
	
		dnl Add the coverage flags (clang, gcc)
		CFLAGS="$CFLAGS --coverage"
		LDFLAGS="$LDFLAGS --coverage"
	])
]) # AC_CODE_COVERAGE
