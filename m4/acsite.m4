# check for the presence of help2man
# if it is available then set MANPAGES to 
# the list of man page files to create
#
# AC_PROG_HELP2MAN(list-of-man-pages)

AC_DEFUN([AC_PROG_HELP2MAN],
[{
AC_CHECK_PROGS([HELP2MAN], [help2man])
if ! test -z "$HELP2MAN" 
then
AC_SUBST(MANPAGES, $1)
fi
}])
