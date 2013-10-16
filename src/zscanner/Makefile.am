ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
AM_CFLAGS = -I$(top_srcdir)/src

noinst_LTLIBRARIES = libzscanner.la

EXTRA_DIST =				\
	scanner.rl			\
	scanner_body.rl

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

include $(srcdir)/tests/Makefile.inc
