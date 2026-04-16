knot_modules_localalias_la_SOURCES = knot/modules/localalias/localalias.c
EXTRA_DIST +=                        knot/modules/localalias/localalias.rst

if STATIC_MODULE_localalias
libknotd_la_SOURCES += $(knot_modules_localalias_la_SOURCES)
endif

if SHARED_MODULE_localalias
knot_modules_localalias_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_localalias_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/localalias.la
endif
