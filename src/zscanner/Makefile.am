ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

noinst_PROGRAMS = zscanner-tool
noinst_LTLIBRARIES = libzscanner.la

EXTRA_DIST =				\
	scanner.rl			\
	scanner_body.rl			\
	test/run_tests.sh		\
	test/cases

if HAVE_RAGEL
BUILT_SOURCES = scanner.c
CLEANFILES = scanner.c

scanner.c: scanner.rl scanner_body.rl
	$(RAGEL) $(FSM_TYPE) -s -o $@ $(srcdir)/scanner.rl
endif

zscanner_tool_SOURCES =			\
	test/zscanner-tool.c		\
	test/tests.h			\
	test/tests.c			\
	test/processing.h		\
	test/processing.c

libzscanner_la_SOURCES =		\
	../common/descriptor.h		\
	../common/descriptor.c		\
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
