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
# with this program.  If not, see <http://www.gnu.org/licenses/>.

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
		dnl Check whether gcc is used
		AS_IF([test "$GCC" = "no"], [
			AC_MSG_ERROR([compiling with gcc is required for gcov code coverage])
		])

		AC_CHECK_PROG([LCOV], [lcov], [lcov])
		AC_CHECK_PROG([GENHTML], [genhtml], [genhtml])		

		lcov_version_list="1.6 1.7 1.8 1.9 1.10"

		AS_IF([test "$LCOV"], [
			AC_CACHE_CHECK([for lcov version], ac_cv_lvoc_version, [
				ac_cv_lcov_version=invalid
				lcov_version=`$LCOV -v 2>/dev/null | $SED -e 's/^.* //'`
			for lcov_check_version in $lcov_version_list; do
					if test "$lcov_version" = "$lcov_check_version"; then
						ac_cv_lcov_version="$lcov_check_version (ok)"
					fi
				done
			])
		],[
			AC_MSG_ERROR([You must have one of the following lcov versions installed: $lcov_version_list to enable gcov code coverage reporting])
		])
	
		AS_CASE([$ac_cv_lcov_version],
			[""|invalid], [AC_MSG_ERROR([You must have one of the following lcov versions installed: $lcov_version_list to enable gcov code coverage reporting])
		])
	
		AS_IF([test -z "$GENHTML"], [
			AC_MSG_ERROR([Could not find genhtml from the lcov package])
		])
	
		dnl Remove all optimization flags from CFLAGS
		changequote({,})
		CFLAGS=`echo "$CFLAGS" | $SED -e 's/-O[0-9]*//g'`
		changequote([,])
	
		dnl Add the special gcc flags
		CODE_COVERAGE_CFLAGS="-O0 -g -fprofile-arcs -ftest-coverage"
		CODE_COVERAGE_LDFLAGS="-lgcov"
	
		AC_SUBST([CODE_COVERAGE_CFLAGS])
		AC_SUBST([CODE_COVERAGE_LDFLAGS])
	])
]) # AC_CODE_COVERAGE
