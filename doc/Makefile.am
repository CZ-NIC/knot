MANPAGES_RST = \
	reference.rst		\
	man_knotc.rst		\
	man_knotd.rst		\
	man_kcatalogprint.rst	\
	man_keymgr.rst		\
	man_kjournalprint.rst	\
	man_kdig.rst		\
	man_khost.rst		\
	man_knsupdate.rst	\
	man_knsec3hash.rst	\
	man_kzonecheck.rst	\
	man_kzonesign.rst	\
	man_kxdpgun.rst

EXTRA_DIST = \
	conf.py			\
	\
	appendices.rst		\
	configuration.rst	\
	index.rst		\
	installation.rst	\
	introduction.rst	\
	migration.rst		\
	modules.rst.in		\
	operation.rst		\
	reference.rst		\
	requirements.rst	\
	troubleshooting.rst	\
	utilities.rst		\
	\
	$(MANPAGES_RST)		\
	\
	logo.pdf		\
	logo.svg		\
	\
	ext/ignore_panels.py	\
	theme_epub		\
	theme_html

SPHINX_V = $(SPHINX_V_@AM_V@)
SPHINX_V_ = $(SPHINX_V_@AM_DEFAULT_V@)
SPHINX_V_0 = -q
SPHINX_V_1 = -n

AM_V_SPHINX = $(AM_V_SPHINX_@AM_V@)
AM_V_SPHINX_ = $(AM_V_SPHINX_@AM_DEFAULT_V@)
AM_V_SPHINX_0 = @echo "  SPHINX   $@";

SPHINXBUILDDIR = $(builddir)/_build

_SPHINXOPTS    = -c $(srcdir) \
	         -a \
	         $(SPHINX_V) \
	         -D version="$(VERSION)" \
	         -D today="$(RELEASE_DATE)" \
	         -D release="$(VERSION)"

ALLSPHINXOPTS  = $(_SPHINXOPTS) \
	         $(SPHINXOPTS) \
	         $(srcdir)

man_SPHINXOPTS = $(_SPHINXOPTS) \
	         -D extensions="ignore_panels" \
	         $(SPHINXOPTS) \
	         $(srcdir)

.PHONY: html-local singlehtml pdf-local epub man install-html-local install-singlehtml install-pdf-local install-epub

man_MANS =

if HAVE_DOCS

if HAVE_DAEMON
man_MANS += \
	man/knot.conf.5		\
	man/knotc.8		\
	man/knotd.8
endif # HAVE_DAEMON

if HAVE_UTILS
if HAVE_DAEMON
man_MANS += \
	man/kcatalogprint.8	\
	man/keymgr.8		\
	man/kjournalprint.8	\
	man/kzonecheck.1	\
	man/kzonesign.1
endif # HAVE_DAEMON

man_MANS += \
	man/kdig.1		\
	man/khost.1		\
	man/knsupdate.1		\
	man/knsec3hash.1

if ENABLE_XDP
man_MANS += man/kxdpgun.8
endif # ENABLE_XDP
endif # HAVE_UTILS

if HAVE_SPHINX
html-local:
	$(AM_V_SPHINX)$(SPHINXBUILD) -b html -d $(SPHINXBUILDDIR)/doctrees/html $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/html
	@echo "The HTML documentation has been built in $(SPHINXBUILDDIR)/html/"

install-html-local:
	$(INSTALL) -d $(DESTDIR)/$(docdir) $(DESTDIR)/$(docdir)/_static $(DESTDIR)/$(docdir)/_sources
	$(INSTALL) -D $(SPHINXBUILDDIR)/html/*.html $(DESTDIR)/$(docdir)/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/html/_sources/* $(DESTDIR)/$(docdir)/_sources/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/html/_static/* $(DESTDIR)/$(docdir)/_static/

singlehtml:
	$(AM_V_SPHINX)$(SPHINXBUILD) -b singlehtml -d $(SPHINXBUILDDIR)/doctrees/singlehtml $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/singlehtml
	@echo "The single HTML documentation has been built in $(SPHINXBUILDDIR)/singlehtml/"

install-singlehtml: singlehtml
	$(INSTALL) -d $(DESTDIR)/$(docdir) $(DESTDIR)/$(docdir)/_static
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/singlehtml/*.html $(DESTDIR)/$(docdir)/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/singlehtml/_static/* $(DESTDIR)/$(docdir)/_static/

epub:
	$(AM_V_SPHINX)$(SPHINXBUILD) -b epub -A today=$(RELEASE_DATE) -d $(SPHINXBUILDDIR)/doctrees/epub $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/epub
	@echo "The EPUB documentation has been built in $(SPHINXBUILDDIR)/epub/"

install-epub:
	$(INSTALL) -d $(DESTDIR)/$(docdir)
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/epub/KnotDNS.epub $(DESTDIR)/$(docdir)/

if HAVE_PDFLATEX
pdf-local:
	$(AM_V_SPHINX)$(SPHINXBUILD) -b latex -d $(SPHINXBUILDDIR)/doctrees/latex $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/latex
	$(MAKE) -C $(SPHINXBUILDDIR)/latex all-pdf
	@echo "The PDF documentation has been built in $(SPHINXBUILDDIR)/latex/"

install-pdf-local:
	$(INSTALL) -d $(DESTDIR)/$(docdir)
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/latex/KnotDNS.pdf $(DESTDIR)/$(docdir)/

else
pdf-local install-pdf-local:
	@echo "Install 'pdflatex' and re-run configure to be able to generate PDF documentation!"
endif # HAVE_PDFLATEX

man: $(man_MANS)
$(man_MANS)&: $(MANPAGES_RST)
	$(AM_V_SPHINX)$(SPHINXBUILD) -b man -d $(SPHINXBUILDDIR)/doctrees/man $(man_SPHINXOPTS) $(SPHINXBUILDDIR)/man
	@mkdir -p man
	@for f in $(SPHINXBUILDDIR)/man/*; do \
	  sed -e 's,[@]config_dir@,$(config_dir),' \
	      -e 's,[@]storage_dir@,$(storage_dir),' \
	      -e 's,[@]run_dir@,$(run_dir),' \
	      -e 's,[@]conf_mapsize@,$(conf_mapsize),' "$$f" > "man/$$(basename $$f)"; \
	done

else
html-local singlehtml pdf-local epub man install-html-local install-singlehtml install-pdf-local install-epub:
	@echo "Install 'sphinx-build' and re-run configure to be able to generate documentation!"

$(man_MANS)&:
	@if [ ! -f "$@" ]; then \
	  echo "Install 'sphinx-build' or disable documentation and re-run configure to generate man pages!"; \
	fi
endif # HAVE_SPHINX

endif # HAVE_DOCS

EXTRA_DIST += \
	$(man_MANS)

clean-local:
	-rm -rf $(SPHINXBUILDDIR)
	-rm -rf man
