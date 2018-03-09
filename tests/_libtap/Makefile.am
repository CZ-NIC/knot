AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(top_srcdir)/src

libtap_la_SOURCES = \
	tap/basic.c		\
	tap/basic.h		\
	tap/files.c		\
	tap/files.h		\
	tap/float.c		\
	tap/float.h		\
	tap/macros.h

check_LTLIBRARIES = libtap.la

check_PROGRAMS = \
	runtests

EXTRA_DIST = \
	tap/libtap.sh

check-compile: $(check_LTLIBRARIES) $(check_PROGRAMS)
