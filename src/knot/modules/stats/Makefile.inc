knot_modules_stats_la_SOURCES = knot/modules/stats/stats.c

if STATIC_MODULE_stats
libknotd_la_SOURCES += $(knot_modules_stats_la_SOURCES)
endif

if SHARED_MODULE_stats
knot_modules_stats_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_stats_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/stats.la
endif
