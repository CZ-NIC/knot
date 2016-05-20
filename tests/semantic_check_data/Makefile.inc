check_SCRIPTS = \
	semantic_check

CLEANFILES += $(check_SCRIPTS)

edit = $(SED) \
	-e 's|@top_srcdir[@]|$(abs_top_srcdir)|g' \
	-e 's|@top_builddir[@]|$(abs_top_builddir)|g'

semantic_check: $(top_srcdir)/tests/semantic_check.in
	$(edit) < $(top_srcdir)/tests/semantic_check.in > $(top_builddir)/tests/semantic_check
	chmod +x $(top_builddir)/tests/semantic_check

EXTRA_DIST = \
	semantic_check.in \
	semantic_check_data
