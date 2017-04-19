knot_modules_synthrecord_la_SOURCES = knot/modules/synthrecord/synthrecord.c

if STATIC_MODULE_synthrecord
libknotd_la_SOURCES += $(knot_modules_synthrecord_la_SOURCES)
endif

if SHARED_MODULE_synthrecord
knot_modules_synthrecord_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_synthrecord_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
knot_modules_synthrecord_la_LIBADD = libcontrib.la
pkglib_LTLIBRARIES += knot/modules/synthrecord.la
endif
