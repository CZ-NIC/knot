knot_modules_whoami_la_SOURCES = knot/modules/whoami/whoami.c

if STATIC_MODULE_whoami
libknotd_la_SOURCES += $(knot_modules_whoami_la_SOURCES)
endif

if SHARED_MODULE_whoami
knot_modules_whoami_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_whoami_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/whoami.la
endif
