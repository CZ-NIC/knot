# -*- mode: makefile; -*-
check_PROGRAMS = \
	tests/runtests \
	tests/zscanner-tool

dist_check_SCRIPTS = \
	tests/zscanner

check_LIBRARIES = tests/tap/libtap.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-DSBINDIR='"$(sbindir)"'

tests_runtests_CPPFLAGS = \
	-DSOURCE='"$(abs_srcdir)/tests"' \
	-DBUILD='"$(abs_builddir)/tests"'

tests_tap_libtap_a_CPPFLAGS = -I$(abs_srcdir)/tests
tests_tap_libtap_a_SOURCES = \
	tests/tap/basic.c tests/tap/basic.h \
	tests/tap/float.c tests/tap/float.h \
	tests/tap/macros.h

if FAST_PARSER
tests/data/06-0_INCLUDE.out: tests/data/06-0_INCLUDE.out.g2
	cp $@.g2 $@
else
tests/data/06-0_INCLUDE.out: tests/data/06-0_INCLUDE.out.t0
	cp $@.t0 $@
endif

check-local: $(check_PROGRAMS)
	cd tests && ./runtests -l $(abs_srcdir)/tests/TESTS

tests_zscanner_tool_SOURCES =		\
	tests/zscanner-tool.c		\
	tests/tests.h			\
	tests/tests.c			\
	tests/processing.h		\
	tests/processing.c

tests_zscanner_tool_LDADD = libzscanner.la @LIBOBJS@

BUILT_SOURCES += tests/data/06-0_INCLUDE.out
CLEANFILES += tests/data/06-0_INCLUDE.out
EXTRA_DIST += 				\
	tests/TESTS			\
	tests/zscanner-TESTS		\
	tests/data			\
	tests/tap/libtap.sh		\
	tests/data/06-0_INCLUDE.out.g2	\
	tests/data/06-0_INCLUDE.out.t0
