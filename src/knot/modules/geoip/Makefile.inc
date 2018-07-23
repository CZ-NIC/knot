knot_modules_geoip_la_SOURCES = knot/modules/geoip/geoip.c \
                                knot/modules/geoip/geodb.c \
                                knot/modules/geoip/geodb.h
EXTRA_DIST +=                   knot/modules/geoip/geoip.rst

if STATIC_MODULE_geoip
libknotd_la_SOURCES += $(knot_modules_geoip_la_SOURCES)
libknotd_la_CPPFLAGS += $(libmaxminddb_CFLAGS)
libknotd_la_LIBADD += $(libmaxminddb_LIBS)
endif

if SHARED_MODULE_geoip
knot_modules_geoip_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_geoip_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/geoip.la
endif
