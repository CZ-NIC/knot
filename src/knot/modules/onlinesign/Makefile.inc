knot_modules_onlinesign_la_SOURCES = knot/modules/onlinesign/onlinesign.c \
                                     knot/modules/onlinesign/nsec_next.c \
                                     knot/modules/onlinesign/nsec_next.h
EXTRA_DIST +=                        knot/modules/onlinesign/onlinesign.rst

if STATIC_MODULE_onlinesign
libknotd_la_SOURCES += $(knot_modules_onlinesign_la_SOURCES)
endif

if SHARED_MODULE_onlinesign
knot_modules_onlinesign_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_onlinesign_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
knot_modules_onlinesign_la_LIBADD = libcontrib.la
pkglib_LTLIBRARIES += knot/modules/onlinesign.la
endif
