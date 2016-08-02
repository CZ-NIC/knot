ACLOCAL_AMFLAGS = -I m4
SUBDIRS = libtap src tests tests-fuzz samples doc

.PHONY: singlehtml install-singlehtml
singlehtml install-singlehtml:
	$(MAKE) -C doc $@

.PHONY: check-compile
check-compile:
	$(MAKE) $(AM_MAKEFLAGS) -C libtap $@
	$(MAKE) $(AM_MAKEFLAGS) -C src $@
	$(MAKE) $(AM_MAKEFLAGS) -C tests $@
	$(MAKE) $(AM_MAKEFLAGS) -C tests-fuzz $@

AM_DISTCHECK_CONFIGURE_FLAGS =

CODE_COVERAGE_INFO = coverage.info
CODE_COVERAGE_HTML = coverage.html
CODE_COVERAGE_DIRS =		\
	src/contrib		\
	src/dnssec/lib		\
	src/dnssec/shared	\
	src/knot		\
	src/libknot		\
	src/zscanner

code_coverage_quiet = --quiet

check-code-coverage:
if CODE_COVERAGE_ENABLED
	$(MAKE) $(AM_MAKEFLAGS) code-coverage-initial
	-$(MAKE) $(AM_MAKEFLAGS) -k check
	$(MAKE) $(AM_MAKEFLAGS) code-coverage-capture
	$(MAKE) $(AM_MAKEFLAGS) code-coverage-html
	$(MAKE) $(AM_MAKEFLAGS) code-coverage-summary
else
	@echo "You need to run configure with --enable-code-coverage to enable code coverage"
endif

code-coverage-initial:
if CODE_COVERAGE_ENABLED
	$(LCOV) $(code_coverage_quiet) \
		--no-external \
		$(foreach dir, $(CODE_COVERAGE_DIRS), --directory $(top_builddir)/$(dir)) \
		--capture --initial \
		--ignore-errors source \
		--no-checksum \
		--compat-libtool \
		--output-file $(CODE_COVERAGE_INFO)
else
	@echo "You need to run configure with --enable-code-coverage to enable code coverage"
endif

code-coverage-capture:
if CODE_COVERAGE_ENABLED
	$(LCOV) $(code_coverage_quiet) \
		--no-external \
		$(foreach dir, $(CODE_COVERAGE_DIRS), --directory $(builddir)/$(dir)) \
		--capture \
		--ignore-errors source \
		--no-checksum \
		--compat-libtool \
		--output-file $(CODE_COVERAGE_INFO)
else
	@echo "You need to run configure with --enable-code-coverage to enable code coverage"
endif

code-coverage-html:
if CODE_COVERAGE_ENABLED
	@echo "Generating code coverage HTML report (this might take a while)"
	LANG=C $(GENHTML) $(code_coverage_quiet) \
		--output-directory $(CODE_COVERAGE_HTML) \
		--title "Knot DNS $(PACKAGE_VERSION) Code Coverage" \
		--legend --show-details \
		--ignore-errors source \
		$(CODE_COVERAGE_INFO)
else
	@echo "You need to run configure with --enable-code-coverage to enable code coverage"
endif

code-coverage-summary:
if CODE_COVERAGE_ENABLED
	$(LCOV) \
		--summary $(CODE_COVERAGE_INFO)
else
	@echo "You need to run configure with --enable-code-coverage to enable code coverage"
endif

if CODE_COVERAGE_ENABLED
clean-local: code-coverage-clean
	-find . -name "*.gcno" -delete
code-coverage-clean:
	-$(LCOV) --directory $(top_builddir) -z
	-rm -rf $(CODE_COVERAGE_INFO) $(CODE_COVERAGE_HTML)
	-find . -name "*.gcda" -o -name "*.gcov" -delete
endif


.PHONY: check-code-coverage code-coverage-initial code-coverage-capture code-coverage-html code-coverage-summary code-coverage-clean
.NOTPARALLEL: clean
