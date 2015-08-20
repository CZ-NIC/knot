AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/dnssec/lib 

LDADD = \
	$(top_builddir)/src/libknot.la

check_PROGRAMS = \
	knotd_stdio \
	packet

knotd_stdio_SOURCES = wrap/server.c wrap/tcp-handler.c wrap/udp-handler.c
knotd_stdio_CPPFLAGS = $(AM_CPPFLAGS) $(liburcu_CFLAGS)
knotd_stdio_LDADD = \
	$(top_builddir)/src/knot/knotd-main.o \
	$(top_builddir)/src/libknotd.la $(liburcu_LIBS)
