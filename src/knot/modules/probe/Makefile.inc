knot_modules_probe_la_SOURCES = knot/modules/probe/probe.c
EXTRA_DIST +=                   knot/modules/probe/probe.rst

if STATIC_MODULE_probe
libknotd_la_SOURCES += $(knot_modules_probe_la_SOURCES)
endif

if SHARED_MODULE_probe
knot_modules_probe_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_probe_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/probe.la
endif
