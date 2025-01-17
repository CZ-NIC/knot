AM_CPPFLAGS = -include $(top_builddir)/src/config.h
AM_LDFLAGS = $(LT_NO_UNDEFINED)

if ENABLE_REDIS
pkglib_LTLIBRARIES = knot.la
knot_la_SOURCES = knot.c

knot_la_CPPFLAGS = $(AM_CPPFLAGS) $(libhiredis_CFLAGS)
knot_la_LDFLAGS  = $(AM_LDFLAGS) -module -shared -avoid-version \
                   $(libhiredis_LDFLAGS) ../libknot.la ../libdnssec.la
endif
