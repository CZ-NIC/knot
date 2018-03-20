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

if SANITIZE_FUZZER
packet_libfuzzer_LDFLAGS = -fsanitize=fuzzer
zscanner_libfuzzer_LDFLAGS = -fsanitize=fuzzer
else
packet_libfuzzer_SOURCES += main.c
zscanner_libfuzzer_SOURCES += main.c
AM_CPPFLAGS += -DTEST_RUN
TESTS = $(FUZZERS)
endif

check-compile: $(check_PROGRAMS)
