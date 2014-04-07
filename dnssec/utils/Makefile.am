AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(srcdir)/../shared \
	-I$(srcdir)/../lib/dnssec \
	-I$(srcdir)/../lib

LDADD = \
	$(builddir)/../libshared.la \
	$(builddir)/../libdnssec.la

bin_PROGRAMS = \
	parsekey
