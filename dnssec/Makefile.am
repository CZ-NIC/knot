SUBDIRS = tests

# Knot DNS common sources depedency (temporary)
#AM_CPPFLAGS = -I$(top_srcdir)/src

lib_LTLIBRARIES = libdnssec.la

libdnssec_la_CFLAGS = $(AM_CFLAGS) $(GNUTLS_CFLAGS) -fvisibility=hidden
libdnssec_la_LDFLAGS = $(GNUTLS_LIBS) -version-info 0:1:0
libdnssec_la_SOURCES =	\
	src/key.c	\
	src/key.h
