AM_CPPFLAGS = -I$(top_srcdir)/src -include $(top_builddir)/src/config.h
AM_LDFLAGS = $(LT_NO_UNDEFINED)

pkglibdir = ${redis_dir}

if ENABLE_REDIS_MODULE
pkglib_LTLIBRARIES = knot.la
knot_la_SOURCES = \
        arg.h \
        error.h \
        internal.h \
        knot.c \
        knot.h \
        libs.h \
        type_diff.h \
        type_rrset.h

knot_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(gnutls_CFLAGS)
knot_la_LDFLAGS  = $(AM_LDFLAGS) -module -shared -avoid-version
endif
