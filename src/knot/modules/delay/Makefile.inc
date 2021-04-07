knot_modules_delay_la_SOURCES = knot/modules/delay/delay.c
EXTRA_DIST +=                    knot/modules/delay/delay.rst

if STATIC_MODULE_delay
libknotd_la_SOURCES += $(knot_modules_delay_la_SOURCES)
endif

if SHARED_MODULE_delay
knot_modules_delay_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_delay_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS) $(DELAY_CFLAGS)
knot_modules_delay_la_LIBADD = $(DELAY_LIBS)
pkglib_LTLIBRARIES += knot/modules/delay.la
endif
