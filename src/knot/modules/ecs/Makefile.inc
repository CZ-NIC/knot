knot_modules_ecs_la_SOURCES = knot/modules/ecs/ecs.c
EXTRA_DIST +=                 knot/modules/ecs/ecs.rst

if STATIC_MODULE_ecs
libknotd_la_SOURCES += $(knot_modules_ecs_la_SOURCES)
endif

if SHARED_MODULE_ecs
knot_modules_ecs_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_ecs_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/ecs.la
endif
