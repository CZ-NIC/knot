AM_CPPFLAGS = -I$(top_srcdir)/src -include $(top_builddir)/src/config.h
AM_LDFLAGS = $(LT_NO_UNDEFINED)

pkglibdir = ${libdir}/knot/redis

if ENABLE_REDIS_MODULE
pkglib_LTLIBRARIES = knot.la
knot_la_SOURCES = knot.c

knot_la_CPPFLAGS = $(AM_CPPFLAGS)
knot_la_LDFLAGS  = $(AM_LDFLAGS) -module -shared -avoid-version
endif
