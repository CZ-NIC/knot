AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h	\
	-I$(top_srcdir)/src			\
	-I$(top_srcdir)/src/dnssec/lib		\
	-DCONFIG_DIR='"${config_dir}"'		\
	-DSTORAGE_DIR='"${storage_dir}"'	\
	-DRUN_DIR='"${run_dir}"'		\
	-DSRCDIR=\"$(abs_srcdir)\"

FUZZERS = \
	fuzz_packet	\
	fuzz_zscanner

check_PROGRAMS = $(FUZZERS)

fuzz_packet_SOURCES = fuzz_packet.c
fuzz_packet_LDADD = $(top_builddir)/src/libknot.la

fuzz_zscanner_SOURCES = fuzz_zscanner.c
fuzz_zscanner_LDADD = $(top_builddir)/src/zscanner/libzscanner.la

if OSS_FUZZ

# CFLAGS, LDFLAGS, etc. are defined by the oss-fuzz environment; just link
# in the fuzzing engine

fuzz_packet_LDADD += ${LIB_FUZZING_ENGINE} -lc++
fuzz_zscanner_LDADD += ${LIB_FUZZING_ENGINE} -lc++

else

if SANITIZE_FUZZER

fuzz_packet_LDFLAGS = -fsanitize=fuzzer
fuzz_zscanner_LDFLAGS = -fsanitize=fuzzer

# Ensure that fuzzers execute successfully with a benign input

TESTS = check/check_fuzzers.test
EXTRA_DIST = check/check_fuzzers.test

else

fuzz_packet_SOURCES += main.c
fuzz_zscanner_SOURCES += main.c
AM_CPPFLAGS += -DTEST_RUN
TESTS = $(FUZZERS)

endif # if SANITIZE_FUZZER

endif # if OSS_FUZZ
