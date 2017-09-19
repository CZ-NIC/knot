knot_modules_rosedb_la_SOURCES = knot/modules/rosedb/rosedb.c
EXTRA_DIST +=                    knot/modules/rosedb/rosedb.rst

rosedb_tool_SOURCES = knot/modules/rosedb/rosedb_tool.c
rosedb_tool_LDADD = libknotd.la libcontrib.la
rosedb_tool_LDFLAGS = $(AM_LDFLAGS) $(lmdb_LIBS)
rosedb_tool_CPPFLAGS = $(AM_CPPFLAGS) -DKNOTD_MOD_STATIC
rosedb_tool_CFLAGS = $(AM_CFLAGS) $(lmdb_CFLAGS)

if STATIC_MODULE_rosedb
libknotd_la_SOURCES += $(knot_modules_rosedb_la_SOURCES)

if HAVE_UTILS
bin_PROGRAMS += rosedb_tool
endif
endif

if SHARED_MODULE_rosedb
knot_modules_rosedb_la_LDFLAGS = $(KNOTD_MOD_LDFLAGS)
knot_modules_rosedb_la_CPPFLAGS = $(KNOTD_MOD_CPPFLAGS) $(lmdb_CFLAGS)
knot_modules_rosedb_la_LIBADD = libcontrib.la
pkglib_LTLIBRARIES += knot/modules/rosedb.la

if HAVE_UTILS
bin_PROGRAMS += rosedb_tool
endif
endif
