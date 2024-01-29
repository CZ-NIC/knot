knot_modules_authsignal_la_SOURCES = knot/modules/authsignal/authsignal.c
EXTRA_DIST +=                        knot/modules/authsignal/authsignal.rst

if STATIC_MODULE_authsignal
libknotd_la_SOURCES += $(knot_modules_authsignal_la_SOURCES)
endif

if SHARED_MODULE_authsignal
knot_modules_authsignal_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_authsignal_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
pkglib_LTLIBRARIES += knot/modules/authsignal.la
endif
