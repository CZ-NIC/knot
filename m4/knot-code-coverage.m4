# Copyright 2014 CZ.NIC, z.s.p.o.
#
# This program is free software: you can redistribute it and/or modify it 
# under the terms of the GNU General Public License version 3, as published 
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranties of 
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR 
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along 
# with this program.  If not, see <https://www.gnu.org/licenses/>.

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
