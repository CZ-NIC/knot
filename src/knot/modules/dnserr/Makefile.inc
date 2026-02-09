knot_modules_dnserr_la_SOURCES = knot/modules/dnserr/dnserr.c
EXTRA_DIST +=                    knot/modules/dnserr/dnserr.rst

if STATIC_MODULE_dnserr
libknotd_la_SOURCES += $(knot_modules_dnserr_la_SOURCES)
endif

if SHARED_MODULE_dnserr
knot_modules_dnserr_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_dnserr_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/dnserr.la
endif
