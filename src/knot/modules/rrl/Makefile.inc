knot_modules_rrl_la_SOURCES = knot/modules/rrl/rrl.c \
                              knot/modules/rrl/functions.c \
                              knot/modules/rrl/functions.h \
                              knot/modules/rrl/kru-generic.c \
                              knot/modules/rrl/kru-avx2.c \
                              knot/modules/rrl/kru.h
noinst_HEADERS =              knot/modules/rrl/kru.inc.c
EXTRA_DIST +=                 knot/modules/rrl/rrl.rst

if STATIC_MODULE_rrl
libknotd_la_SOURCES += $(knot_modules_rrl_la_SOURCES)
libknotd_la_LIBADD += $(math_LIBS)
endif

if SHARED_MODULE_rrl
knot_modules_rrl_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_rrl_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS)
knot_modules_rrl_la_LIBADD = $(libcontrib_LIBS) $(math_LIBS)
pkglib_LTLIBRARIES += knot/modules/rrl.la
endif
