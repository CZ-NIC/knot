LDADD = \
	$(top_builddir)/src/zscanner/libzscanner.la



tests_zscanner_tool_SOURCES = \
	tests/zscanner-tool.c	\
	tests/tests.h		\
	tests/tests.c		\
	tests/processing.h	\
	tests/processing.c

tests_zscanner_tool_CFLAGS = $(CODE_COVERAGE_CFLAGS)

check_PROGRAMS = \
	tests/zscanner-tool

check_SCRIPTS = \
	tests/unittests

CLEANFILES += $(check_SCRIPTS)

edit = sed \
	-e 's|@top_srcdir[@]|$(abs_top_srcdir)|g' \
	-e 's|@top_builddir[@]|$(abs_top_builddir)|g'

tests/unittests:
	$(edit) < $(top_srcdir)/src/zscanner/$@.in > $(top_builddir)/src/zscanner/$@
	chmod +x $(top_builddir)/src/zscanner/$@

check-compile-only: $(check_SCRIPTS) $(check_PROGRAMS)

check-local: $(check_PROGRAMS)
	$(top_builddir)/libtap/runtests \
	-s $(top_srcdir)/src/zscanner/tests \
	-b $(top_builddir)/src/zscanner/tests \
	$(top_builddir)/src/zscanner/tests/unittests

EXTRA_DIST += \
	tests/unittests.in \
	tests/TESTS \
	tests/data
