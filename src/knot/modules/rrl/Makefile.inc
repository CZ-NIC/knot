knot_modules_rrl_la_SOURCES = knot/modules/rrl/rrl.c \
                              knot/modules/rrl/functions.c \
                              knot/modules/rrl/functions.h
EXTRA_DIST +=                 knot/modules/rrl/rrl.rst

if STATIC_MODULE_rrl
libknotd_la_SOURCES += $(knot_modules_rrl_la_SOURCES)
endif

if SHARED_MODULE_rrl
knot_modules_rrl_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_rrl_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
knot_modules_rrl_la_LIBADD = libcontrib.la
pkglib_LTLIBRARIES += knot/modules/rrl.la
endif
