LDADD = \
	$(top_builddir)/src/zscanner/libzscanner.la

tests_zscanner_tool_SOURCES = \
	tests/zscanner-tool.c	\
	tests/tests.h		\
	tests/tests.c		\
	tests/processing.h	\
	tests/processing.c

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

check-compile: $(check_SCRIPTS) $(check_PROGRAMS)


AM_V_RUNTESTS = $(am__v_RUNTESTS_@AM_V@)
am__v_RUNTESTS_ = $(am__v_RUNTESTS_@AM_DEFAULT_V@)
am__v_RUNTESTS_0 =
am__v_RUNTESTS_1 = RET=$$?; if [ "$$RET" != "0" ]; then cat "$(top_builddir)/src/zscanner/tests/runtests.log"; exit $$RET; fi
check-local: $(check_PROGRAMS)
	$(top_builddir)/libtap/runtests \
	-s $(top_srcdir)/src/zscanner/tests \
	-b $(top_builddir)/src/zscanner/tests \
	-L $(top_builddir)/src/zscanner/tests/runtests.log \
	$(top_builddir)/src/zscanner/tests/unittests; \
	$(AM_V_RUNTESTS)

EXTRA_DIST += \
	tests/unittests.in \
	tests/TESTS \
	tests/data
