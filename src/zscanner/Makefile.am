ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
AM_CFLAGS = -I$(top_srcdir)/src

noinst_LTLIBRARIES = libzscanner.la

EXTRA_DIST =				\
	scanner.rl			\
	scanner_body.rl			\
	scanner.c.g2			\
	scanner.c.t0

BUILT_SOURCES = descriptor.h descriptor.c
CLEANFILES = descriptor.h descriptor.c
nodist_libzscanner_la_SOURCES = descriptor.h descriptor.c

descriptor.h: $(top_srcdir)/src/common/descriptor.h
	cp $(top_srcdir)/src/common/descriptor.h $@

descriptor.c: $(top_srcdir)/src/common/descriptor.c
	cp $(top_srcdir)/src/common/descriptor.c $@

BUILT_SOURCES += scanner.c
CLEANFILES += scanner.c

if HAVE_RAGEL
scanner.c: scanner.rl scanner_body.rl
	$(RAGEL) $(FSM_TYPE) -o $@ $(srcdir)/scanner.rl
else

if G2_PARSER
scanner.c: scanner.c.g2
	cp $@.g2 $@
	@echo "NOTE: Compilation of scanner.c can take several minutes!"
endif

if T0_PARSER
scanner.c: scanner.c.t0
	cp $@.t0 $@
endif

endif #HAVE_RAGEL

libzscanner_la_SOURCES =		\
	zscanner.h			\
	scanner.h			\
	scanner.c			\
	error.h				\
	error.c				\
	file_loader.h			\
	file_loader.c			\
	scanner_functions.h		\
	scanner_functions.c

libzscanner_la_LIBADD = @LIBOBJS@

include $(srcdir)/tests/Makefile.inc
