check_SCRIPTS = \
	knot/test_semantic_check

CLEANFILES += $(check_SCRIPTS)

edit = $(SED) \
	-e 's|@top_srcdir[@]|$(abs_top_srcdir)|g' \
	-e 's|@top_builddir[@]|$(abs_top_builddir)|g'

knot/test_semantic_check: $(top_srcdir)/tests/knot/test_semantic_check.in
	@$(edit) < $(top_srcdir)/tests/knot/test_semantic_check.in > $(top_builddir)/tests/knot/test_semantic_check
	@chmod +x $(top_builddir)/tests/knot/test_semantic_check

EXTRA_DIST = \
	knot/test_semantic_check.in \
	knot/semantic_check_data
