AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h	\
	-I$(top_srcdir)/src			\
	-DCONFIG_DIR='"${config_dir}"'		\
	-DSTORAGE_DIR='"${storage_dir}"'	\
	-DRUN_DIR='"${run_dir}"'		\
	-DSRCDIR=\"$(abs_srcdir)\"

FUZZERS = \
	fuzz_packet		\
	fuzz_zscanner		\
	fuzz_dname_to_str	\
	fuzz_dname_from_str

check_PROGRAMS = $(FUZZERS)

if HAVE_DAEMON
# knotd_stdio (AFL)
check_PROGRAMS += knotd_stdio

nodist_knotd_stdio_SOURCES = knotd_wrap/main.c

knotd_stdio_SOURCES = \
	knotd_wrap/afl-loop.h		\
	knotd_wrap/server.c		\
	knotd_wrap/tcp-handler.c	\
	knotd_wrap/udp-handler.c

knotd_stdio_CPPFLAGS = $(AM_CPPFLAGS) $(liburcu_CFLAGS)
knotd_stdio_LDADD = $(top_builddir)/src/libknotd.la $(top_builddir)/src/libcontrib.la \
                    $(liburcu_LIBS) $(cap_ng_LIBS)

BUILT_SOURCES = knotd_wrap/main.c
CLEANFILES = knotd_wrap/main.c
knotd_wrap/main.c: $(top_builddir)/src/utils/knotd/main.c
	@echo '#include "knotd_wrap/afl-loop.h"' > $@
	@$(SED) -e 's/for (;;)/while (__AFL_LOOP(10000))/' $(top_srcdir)/src/utils/knotd/main.c >> $@
endif HAVE_DAEMON

# Simple function wrappers (AFL, libFuzzer, tests)

fuzz_packet_SOURCES    = fuzz_packet.c
fuzz_packet_CPPFLAGS   = $(AM_CPPFLAGS)
fuzz_packet_LDADD      = $(top_builddir)/src/libknot.la

fuzz_zscanner_SOURCES  = fuzz_zscanner.c
fuzz_zscanner_CPPFLAGS = $(AM_CPPFLAGS)
fuzz_zscanner_LDADD    = $(top_builddir)/src/libzscanner.la

fuzz_dname_to_str_SOURCES  = fuzz_dname_to_str.c
fuzz_dname_to_str_CPPFLAGS = $(AM_CPPFLAGS)
fuzz_dname_to_str_LDADD    = $(top_builddir)/src/libknot.la

fuzz_dname_from_str_SOURCES  = fuzz_dname_from_str.c
fuzz_dname_from_str_CPPFLAGS = $(AM_CPPFLAGS)
fuzz_dname_from_str_LDADD    = $(top_builddir)/src/libknot.la

if OSS_FUZZ

# CFLAGS, LDFLAGS, etc. are defined by the oss-fuzz environment; just link
# in the fuzzing engine

fuzz_packet_LDADD         += ${LIB_FUZZING_ENGINE} -lc++
fuzz_zscanner_LDADD       += ${LIB_FUZZING_ENGINE} -lc++
fuzz_dname_to_str_LDADD   += ${LIB_FUZZING_ENGINE} -lc++
fuzz_dname_from_str_LDADD += ${LIB_FUZZING_ENGINE} -lc++

else

if FUZZER

fuzz_packet_CPPFLAGS   += ${fuzzer_CFLAGS}
fuzz_packet_LDFLAGS     = ${fuzzer_LDFLAGS}

fuzz_zscanner_CPPFLAGS += ${fuzzer_CFLAGS}
fuzz_zscanner_LDFLAGS   = ${fuzzer_LDFLAGS}

fuzz_dname_to_str_CPPFLAGS += ${fuzzer_CFLAGS}
fuzz_dname_to_str_LDFLAGS   = ${fuzzer_LDFLAGS}

fuzz_dname_from_str_CPPFLAGS += ${fuzzer_CFLAGS}
fuzz_dname_from_str_LDFLAGS   = ${fuzzer_LDFLAGS}

# Ensure that fuzzers execute successfully with a benign input

TESTS = check/check_fuzzers.test
EXTRA_DIST = check/check_fuzzers.test

else

fuzz_packet_SOURCES         += main.c
fuzz_zscanner_SOURCES       += main.c
fuzz_dname_to_str_SOURCES   += main.c
fuzz_dname_from_str_SOURCES += main.c

TESTS = $(FUZZERS)

endif # if FUZZER

endif # if OSS_FUZZ

check-compile: $(check_PROGRAMS)
