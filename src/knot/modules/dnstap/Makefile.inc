knot_modules_dnstap_la_SOURCES = knot/modules/dnstap/dnstap.c

if STATIC_MODULE_dnstap
libknotd_la_SOURCES += $(knot_modules_dnstap_la_SOURCES)
libknotd_la_CPPFLAGS += $(DNSTAP_CFLAGS)
libknotd_la_LIBADD += $(DNSTAP_LIBS) contrib/dnstap/libdnstap.la
endif

if SHARED_MODULE_dnstap
knot_modules_dnstap_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_dnstap_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS) $(DNSTAP_CFLAGS)
knot_modules_dnstap_la_LIBADD = $(DNSTAP_LIBS) contrib/dnstap/libdnstap.la libcontrib.la
pkglib_LTLIBRARIES += knot/modules/dnstap.la
endif
