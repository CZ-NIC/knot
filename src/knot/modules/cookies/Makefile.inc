knot_modules_cookies_la_SOURCES = knot/modules/cookies/cookies.c
EXTRA_DIST +=                     knot/modules/cookies/cookies.rst

if STATIC_MODULE_cookies
libknotd_la_SOURCES += $(knot_modules_cookies_la_SOURCES)
endif

if SHARED_MODULE_cookies
knot_modules_cookies_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_cookies_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
knot_modules_cookies_la_LIBADD = libcontrib.la
pkglib_LTLIBRARIES += knot/modules/cookies.la
endif
