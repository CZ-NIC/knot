AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h	\
	-I$(top_srcdir)/src			\
	-I$(top_srcdir)/src/dnssec/lib		\
	-DCONFIG_DIR='"${config_dir}"'          \
	-DSTORAGE_DIR='"${storage_dir}"'        \
	-DRUN_DIR='"${run_dir}"'		\
	-DSRCDIR=\"$(abs_srcdir)\"

FUZZERS = \
	packet_libfuzzer	\
	zscanner_libfuzzer

check_PROGRAMS = $(FUZZERS)

packet_libfuzzer_SOURCES = packet_libfuzzer.c
packet_libfuzzer_LDADD = $(top_builddir)/src/libknot.la

zscanner_libfuzzer_SOURCES = zscanner_libfuzzer.c
zscanner_libfuzzer_LDADD = $(top_builddir)/src/zscanner/libzscanner.la

if OSS_FUZZ

# CFLAGS, LDFLAGS, etc. are defined by the oss-fuzz environment; just link
# in the fuzzing engine

packet_libfuzzer_LDADD += ${LIB_FUZZING_ENGINE} -lc++
zscanner_libfuzzer_LDADD += ${LIB_FUZZING_ENGINE} -lc++

else

if SANITIZE_FUZZER

packet_libfuzzer_LDFLAGS = -fsanitize=fuzzer
zscanner_libfuzzer_LDFLAGS = -fsanitize=fuzzer

# Ensure that fuzzers execute successfully with a benign input

TESTS = check/check_fuzzers.test
EXTRA_DIST = check/check_fuzzers.test

else

packet_libfuzzer_SOURCES += main.c
zscanner_libfuzzer_SOURCES += main.c
AM_CPPFLAGS += -DTEST_RUN
TESTS = $(FUZZERS)

endif # if SANITIZE_FUZZER

endif # if OSS_FUZZ
