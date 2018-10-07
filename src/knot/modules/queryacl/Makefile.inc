knot_modules_queryacl_la_SOURCES = knot/modules/queryacl/queryacl.c \
EXTRA_DIST +=                      knot/modules/queryacl/queryacl.rst

if STATIC_MODULE_queryacl
libknotd_la_SOURCES += $(knot_modules_queryacl_la_SOURCES)
endif

if SHARED_MODULE_queryacl
knot_modules_queryacl_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_queryacl_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/queryacl.la
endif
