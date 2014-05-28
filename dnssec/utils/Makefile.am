noinst_LTLIBRARIES = libutils.la

AM_CFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(srcdir)/../shared \
	-I$(srcdir)/../lib/dnssec \
	-I$(srcdir)/../lib

libutils_la_LIBADD = \
	$(builddir)/../libshared.la \
	$(builddir)/../libdnssec.la \
	$(top_builddir)/src/zscanner/libzscanner.la

libutils_la_CFLAGS = \
	$(AM_CFLAGS) \
	-I$(top_srcdir)/src/zscanner

libutils_la_SOURCES = \
	legacy/legacy.c \
	legacy/legacy.h \
	legacy/privkey.c \
	legacy/privkey.h \
	legacy/pubkey.c \
	legacy/pubkey.h

LDADD = libutils.la

bin_PROGRAMS = \
	generate \
	getpub \
	import \
	keymgr \
	parsekey
