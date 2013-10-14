ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

AM_CPPFLAGS = -I$(top_srcdir)/src/zscanner -I$(top_srcdir)/src -DSYSCONFDIR='"$(sysconfdir)"' -DSBINDIR='"$(sbindir)"'

noinst_PROGRAMS = zscanner-tool
noinst_LTLIBRARIES = libzscanner.la

TESTS = test/run_tests.sh

EXTRA_DIST =				\
	scanner.rl			\
	scanner_body.rl			\
	test/run_tests.sh		\
	test/cases

BUILT_SOURCES = descriptor.h descriptor.c
CLEANFILES = descriptor.h descriptor.c
nodist_libzscanner_la_SOURCES = descriptor.h descriptor.c

descriptor.h: $(top_srcdir)/src/common/descriptor.h
	cp $(top_srcdir)/src/common/descriptor.h $@

descriptor.c: $(top_srcdir)/src/common/descriptor.c
	cp $(top_srcdir)/src/common/descriptor.c $@

if HAVE_RAGEL
BUILT_SOURCES += scanner.c
CLEANFILES += scanner.c scanner.c.in

scanner.c: scanner.rl scanner_body.rl
	$(RAGEL) $(FSM_TYPE) -s -o $@.in $(srcdir)/scanner.rl
	sed '/#line/d' $@.in > $@
endif

zscanner_tool_SOURCES =			\
	test/zscanner-tool.c		\
	test/tests.h			\
	test/tests.c			\
	test/processing.h		\
	test/processing.c

libzscanner_la_SOURCES =		\
	zscanner.h			\
	error.h				\
	error.c				\
	file_loader.h			\
	file_loader.c			\
	scanner.h			\
	scanner.c			\
	scanner_functions.h		\
	scanner_functions.c

libzscanner_la_LIBADD = @LIBOBJS@
zscanner_tool_LDADD = libzscanner.la @LIBOBJS@
