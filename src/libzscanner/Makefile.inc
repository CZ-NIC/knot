lib_LTLIBRARIES += libzscanner.la
pkgconfig_DATA  += libzscanner.pc

libzscanner_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY)
libzscanner_la_LDFLAGS  = $(AM_LDFLAGS) $(libzscanner_VERSION_INFO) $(LDFLAG_EXCLUDE_LIBS)
libzscanner_la_LIBADD   = $(math_LIBS)

EXTRA_DIST += \
	libzscanner/scanner.rl		\
	libzscanner/scanner_body.rl	\
	libzscanner/scanner.c.g2	\
	libzscanner/scanner.c.t0
include_libzscannerdir = $(includedir)/libzscanner

include_libzscanner_HEADERS = \
	libzscanner/error.h		\
	libzscanner/scanner.h		\
	libzscanner/version.h

libzscanner_la_SOURCES = \
	libzscanner/error.c		\
	libzscanner/functions.h		\
	libzscanner/functions.c		\
	$(include_libzscanner_HEADERS)

BUILT_SOURCES += libzscanner/scanner.c
CLEANFILES    += libzscanner/scanner.c

nodist_libzscanner_la_SOURCES = \
	libzscanner/scanner.c

if FAST_PARSER
libzscanner/scanner.c: libzscanner/scanner.c.g2
	@cp $(srcdir)/$@.g2 $@
	@echo "NOTE: Compilation of scanner.c can take several minutes!"
else
libzscanner/scanner.c: libzscanner/scanner.c.t0
	@cp $(srcdir)/$@.t0 $@
endif
