AM_CPPFLAGS = -include $(top_builddir)/src/config.h
AM_LDFLAGS = $(LT_NO_UNDEFINED)

if ENABLE_REDIS
pkglib_LTLIBRARIES = knot.la
knot_la_SOURCES = knot.c

knot_la_CPPFLAGS = $(AM_CPPFLAGS)
knot_la_LDFLAGS  = $(AM_LDFLAGS) -module -shared -avoid-version
endif
