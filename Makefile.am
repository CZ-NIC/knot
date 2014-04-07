ACLOCAL_AMFLAGS = -I m4
SUBDIRS = libtap src/zscanner dnssec src tests samples doc man patches

code_coverage_quiet = --quiet

check-code-coverage:
if CODE_COVERAGE_ENABLED
	-$(MAKE) $(AM_MAKEFLAGS) -k check
	$(MAKE) $(AM_MAKEFLAGS) code-coverage-capture
	$(MAKE) $(AM_MAKEFLAGS) code-coverage-html
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
		--add-tracefile "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-src_capture.info" \
		--add-tracefile "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-conf_capture.info" \
		--add-tracefile "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-zscanner_capture.info" \
		--output-file "$(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage.info"
	-@rm -f $(PACKAGE_NAME)-$(PACKAGE_VERSION)-*_base.info $(PACKAGE_NAME)-$(PACKAGE_VERSION)-*_capture.info
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

if CODE_COVERAGE_ENABLED
clean-local: code-coverage-clean
code-coverage-clean:
	-$(LCOV) --directory $(top_builddir) -z
	-rm -rf $(PACKAGE_NAME)-$(PACKAGE_VERSION)-*_base.info \
	        $(PACKAGE_NAME)-$(PACKAGE_VERSION)-*_coverage.info \
	        $(PACKAGE_NAME)-$(PACKAGE_VERSION)-coverage/
	-find . -name "*.gcda" -o -name "*.gcov" -delete
endif

DISTCHECK_CONFIGURE_FLAGS = --disable-code-coverage

.PHONY: check-code-coverage code-coverage-initial code-coverage-capture code-coverage-html code-coverage-clean
