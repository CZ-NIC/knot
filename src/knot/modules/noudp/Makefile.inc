knot_modules_noudp_la_SOURCES = knot/modules/noudp/noudp.c

if STATIC_MODULE_noudp
libknotd_la_SOURCES += $(knot_modules_noudp_la_SOURCES)
endif

if SHARED_MODULE_noudp
knot_modules_noudp_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_noudp_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/noudp.la
endif
