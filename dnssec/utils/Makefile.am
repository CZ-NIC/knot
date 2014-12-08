noinst_LTLIBRARIES = libutils.la

AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(srcdir)/../shared \
	-I$(srcdir)/../lib/dnssec \
	-I$(srcdir)/../lib \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS)

libutils_la_LIBADD = \
	$(builddir)/../libdnssec.la \
	$(builddir)/../libshared.la \
	$(top_builddir)/src/zscanner/libzscanner.la

libutils_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/zscanner

libutils_la_SOURCES = \
	cmdparse/cmdparse.c \
	cmdparse/cmdparse.h \
	legacy/legacy.c \
	legacy/legacy.h \
	legacy/privkey.c \
	legacy/privkey.h \
	legacy/pubkey.c \
	legacy/pubkey.h \
	print.h

LDADD = libutils.la

bin_PROGRAMS = \
	generate \
	genzonekey \
	getpub \
	import \
	keymgr \
	parsekey
