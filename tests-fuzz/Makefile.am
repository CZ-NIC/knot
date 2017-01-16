AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h	\
	-I$(top_srcdir)/src			\
	-I$(top_srcdir)/src/dnssec/lib		\
        -DCONFIG_DIR='"${config_dir}"'          \
        -DSTORAGE_DIR='"${storage_dir}"'        \
        -DRUN_DIR='"${run_dir}"'

LDADD = \
	$(top_builddir)/src/libknot.la

check_PROGRAMS = \
	knotd_stdio \
	packet

if HAVE_LIBFUZZER
check_PROGRAMS += packet_libfuzzer
packet_libfuzzer_LDADD = $(LDADD) $(libfuzzer_LIBS) -lstdc++
endif

packet_SOURCES = packet.c afl-loop.h
knotd_stdio_SOURCES = wrap/server.c wrap/tcp-handler.c wrap/udp-handler.c afl-loop.h
nodist_knotd_stdio_SOURCES = wrap/main.c
knotd_stdio_CPPFLAGS = $(AM_CPPFLAGS) $(liburcu_CFLAGS)
knotd_stdio_LDADD = \
	$(top_builddir)/src/libknotd.la $(top_builddir)/src/libcontrib.la \
	$(liburcu_LIBS)
BUILT_SOURCES = wrap/main.c
CLEANFILES = wrap/main.c
wrap/main.c: Makefile $(top_builddir)/src/utils/knotd/main.c
	echo '#include "afl-loop.h"' > $@
	$(SED) -e 's/for (;;)/while (__AFL_LOOP(1000))/' $(top_srcdir)/src/utils/knotd/main.c >>$@

check-compile: $(check_PROGRAMS)
