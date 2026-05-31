knot_modules_nodata_la_SOURCES = knot/modules/nodata/nodata.c
EXTRA_DIST +=                    knot/modules/nodata/nodata.rst

if STATIC_MODULE_nodata
libknotd_la_SOURCES += $(knot_modules_nodata_la_SOURCES)
endif

if SHARED_MODULE_nodata
knot_modules_nodata_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_nodata_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/nodata.la
endif
