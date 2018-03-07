check_SCRIPTS = \
	test_semantic_check

CLEANFILES += $(check_SCRIPTS)

edit = $(SED) \
	-e 's|@top_srcdir[@]|$(abs_top_srcdir)|g' \
	-e 's|@top_builddir[@]|$(abs_top_builddir)|g'

test_semantic_check: $(top_srcdir)/tests/test_semantic_check.in
	@$(edit) < $(top_srcdir)/tests/test_semantic_check.in > $(top_builddir)/tests/test_semantic_check
	@chmod +x $(top_builddir)/tests/test_semantic_check

EXTRA_DIST = \
	test_semantic_check.in \
	semantic_check_data
