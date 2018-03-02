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

fuzz_packet_SOURCES    = fuzz_packet.c
fuzz_packet_CPPFLAGS   = $(AM_CPPFLAGS)
fuzz_packet_LDADD      = $(top_builddir)/src/libknot.la

fuzz_zscanner_SOURCES  = fuzz_zscanner.c
fuzz_zscanner_CPPFLAGS = $(AM_CPPFLAGS)
fuzz_zscanner_LDADD    = $(top_builddir)/src/zscanner/libzscanner.la

if OSS_FUZZ

# CFLAGS, LDFLAGS, etc. are defined by the oss-fuzz environment; just link
# in the fuzzing engine

fuzz_packet_LDADD   += ${LIB_FUZZING_ENGINE} -lc++
fuzz_zscanner_LDADD += ${LIB_FUZZING_ENGINE} -lc++

else

if FUZZER

fuzz_packet_CPPFLAGS   += ${fuzzer_CFLAGS}
fuzz_packet_LDFLAGS     = ${fuzzer_LDFLAGS}

fuzz_zscanner_CPPFLAGS += ${fuzzer_CFLAGS}
fuzz_zscanner_LDFLAGS   = ${fuzzer_LDFLAGS}

# Ensure that fuzzers execute successfully with a benign input

TESTS = check/check_fuzzers.test
EXTRA_DIST = check/check_fuzzers.test

else

fuzz_packet_SOURCES   += main.c
fuzz_zscanner_SOURCES += main.c

TESTS = $(FUZZERS)

endif # if FUZZER

endif # if OSS_FUZZ

check-compile: $(check_PROGRAMS)
