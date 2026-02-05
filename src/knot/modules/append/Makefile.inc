knot_modules_append_la_SOURCES = knot/modules/append/append.c
EXTRA_DIST +=                    knot/modules/append/append.rst

if STATIC_MODULE_append
libknotd_la_SOURCES += $(knot_modules_append_la_SOURCES)
endif

if SHARED_MODULE_append
knot_modules_append_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_append_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/append.la
endif
