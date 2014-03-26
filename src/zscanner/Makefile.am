ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(top_srcdir)/src

lib_LTLIBRARIES = libzscanner.la

EXTRA_DIST =				\
	scanner.rl			\
	scanner_body.rl			\
	scanner.c.g2			\
	scanner.c.t0

BUILT_SOURCES = scanner.c
CLEANFILES = scanner.c

if HAVE_RAGEL
scanner.c: scanner.rl scanner_body.rl
	$(RAGEL) $(FSM_TYPE) -o $@ $(srcdir)/scanner.rl
else

if G2_PARSER
scanner.c: scanner.c.g2
	cp $@.g2 $@
endif

if T0_PARSER
scanner.c: scanner.c.t0
	cp $@.t0 $@
endif

endif #HAVE_RAGEL

if G2_PARSER
	@echo "NOTE: Compilation of scanner.c can take several minutes!"
endif

libzscanner_la_SOURCES =		\
	zscanner.h			\
	scanner.h			\
	scanner.c			\
	error.h				\
	error.c				\
	loader.h			\
	loader.c			\
	functions.h			\
	functions.c

libzscanner_la_CFLAGS = $(CODE_COVERAGE_CFLAGS)
libzscanner_la_LDFLAGS =		\
	$(COVERAGE_LDFLAGS)		\
	-version-info 0:1:0		\
	-export-symbols-regex '^zs_'

include $(srcdir)/tests/Makefile.inc
