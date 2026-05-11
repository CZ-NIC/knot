knot_modules_alias_la_SOURCES = knot/modules/alias/alias.c
EXTRA_DIST +=                   knot/modules/alias/alias.rst

if STATIC_MODULE_alias
libknotd_la_SOURCES += $(knot_modules_alias_la_SOURCES)
endif

if SHARED_MODULE_alias
knot_modules_alias_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_alias_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/alias.la
endif
