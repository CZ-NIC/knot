knot_modules_dnsproxy_la_SOURCES = knot/modules/dnsproxy/dnsproxy.c
EXTRA_DIST +=                      knot/modules/dnsproxy/dnsproxy.rst

if STATIC_MODULE_dnsproxy
libknotd_la_SOURCES += $(knot_modules_dnsproxy_la_SOURCES)
endif

if SHARED_MODULE_dnsproxy
knot_modules_dnsproxy_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_dnsproxy_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
knot_modules_dnsproxy_la_LIBADD = libcontrib.la
pkglib_LTLIBRARIES += knot/modules/dnsproxy.la
endif
