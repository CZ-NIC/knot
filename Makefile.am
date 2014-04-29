ACLOCAL_AMFLAGS = -I m4
SUBDIRS = libtap src tests samples doc man patches

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--disable-code-coverage

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
		--directory $(top_builddir)/src/common \
		--directory $(top_builddir)/src/knot \
		--directory $(top_builddir)/src/libknot \
		--capture --initial \
		--ignore-errors source \
		--base-directory $(top_builddir)/src \
		--output-file "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-src_base.info" \
		--test-name "$(PACKAGE_NAME)-$(PACKAGE_VERSION)" \
		--no-checksum --compat-libtool
	$(LCOV) $(code_coverage_quiet) \
		--directory $(top_builddir)/src/knot/conf \
		--capture --initial \
		--ignore-errors source \
		--base-directory $(top_builddir)/src/knot/conf \
		--output-file "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-conf_base.info" \
		--test-name "$(PACKAGE_NAME)-$(PACKAGE_VERSION)" \
		--no-checksum --compat-libtool
	$(LCOV) $(code_coverage_quiet) \
		--directory $(top_builddir)/src/zscanner \
		--capture --initial \
		--ignore-errors source \
		--base-directory $(top_builddir)/src/zscanner \
		--output-file "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-zscanner_base.info" \
		--test-name "$(PACKAGE_NAME)-$(PACKAGE_VERSION)" \
		--no-checksum --compat-libtool
else
	@echo "You need to run configure with --enable-code-coverage to enable code coverage"
endif

code-coverage-capture:
if CODE_COVERAGE_ENABLED
	$(LCOV) $(code_coverage_quiet) \
		--directory $(top_builddir)/src/common \
		--directory $(top_builddir)/src/knot \
		--directory $(top_builddir)/src/libknot \
		--capture \
		--ignore-errors source \
		--base-directory $(top_builddir)/src \
		--output-file "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-src_capture.info" \
		--test-name "$(PACKAGE_NAME)-$(PACKAGE_VERSION)" \
		--no-checksum --compat-libtool
	$(LCOV) $(code_coverage_quiet) \
		--directory $(top_builddir)/src/knot/conf \
		--capture \
		--ignore-errors source \
		--base-directory $(top_builddir)/src/knot/conf \
		--output-file "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-conf_capture.info" \
		--test-name "$(PACKAGE_NAME)-$(PACKAGE_VERSION)" \
		--no-checksum --compat-libtool
	$(LCOV) $(code_coverage_quiet) \
		--directory $(top_builddir)/src/zscanner \
		--capture \
		--ignore-errors source \
		--base-directory $(top_builddir)/src/zscanner \
		--output-file "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-zscanner_capture.info" \
		--test-name "$(PACKAGE_NAME)-$(PACKAGE_VERSION)" \
		--no-checksum --compat-libtool
	$(LCOV) $(code_coverage_quiet) \
		--add-tracefile "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-src_base.info" \
		--add-tracefile "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-conf_base.info" \
		--add-tracefile "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-zscanner_base.info" \
		--add-tracefile "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-src_capture.info" \
		--add-tracefile "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-conf_capture.info" \
		--add-tracefile "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-zscanner_capture.info" \
		--output-file "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage.info"
else
	@echo "You need to run configure with --enable-code-coverage to enable code coverage"
endif

code-coverage-html:
if CODE_COVERAGE_ENABLED
	@echo "Generating code coverage HTML report (this might take a while)"
	@cp src/knot/conf/cf-lex.l src/knot/conf/cf-parse.y src/
	LANG=C $(GENHTML) $(code_coverage_quiet) --prefix $(top_builddir) --output-directory "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage" --title "$(PACKAGE_NAME)-$(PACKAGE_VERSION) Code Coverage" --legend --show-details "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage.info" --ignore-errors source
	-@rm src/cf-lex.l src/cf-parse.y
else
	@echo "You need to run configure with --enable-code-coverage to enable code coverage"
endif

code-coverage-summary:
if CODE_COVERAGE_ENABLED
	$(LCOV) \
		--summary "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage.info"
else
	@echo "You need to run configure with --enable-code-coverage to enable code coverage"
endif

if CODE_COVERAGE_ENABLED
clean-local: code-coverage-clean
	-find . -name "*.gcno" -delete
code-coverage-clean:
	-$(LCOV) --directory $(top_builddir) -z
	-rm -rf $(PACKAGE_NAME)-$(PACKAGE_VERSION)-*_base.info \
	        $(PACKAGE_NAME)-$(PACKAGE_VERSION)-*_capture.info \
	        $(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage.info \
	        $(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage/
	-find . -name "*.gcda" -o -name "*.gcov" -delete
endif

.PHONY: check-code-coverage code-coverage-initial code-coverage-capture code-coverage-html code-coverage-summary code-coverage-clean
