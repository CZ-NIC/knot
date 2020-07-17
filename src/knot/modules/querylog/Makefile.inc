knot_modules_querylog_la_SOURCES = knot/modules/querylog/querylog.c
EXTRA_DIST +=                      knot/modules/querylog/querylog.rst

if STATIC_MODULE_querylog
libknotd_la_SOURCES += $(knot_modules_querylog_la_SOURCES)
endif

if SHARED_MODULE_querylog
knot_modules_querylog_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_querylog_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/querylog.la
endif
