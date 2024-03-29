MANPAGES_IN = \
	man/knot.conf.5in	\
	man/knotc.8in		\
	man/knotd.8in		\
	man/kcatalogprint.8in	\
	man/keymgr.8in		\
	man/kjournalprint.8in	\
	man/kdig.1in		\
	man/khost.1in		\
	man/knsupdate.1in	\
	man/knsec3hash.1in	\
	man/kzonecheck.1in	\
	man/kzonesign.1in	\
	man/kxdpgun.8in

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
	$(MANPAGES_IN)		\
	$(MANPAGES_RST)		\
	\
	logo.pdf		\
	logo.svg		\
	\
	ext/ignore_panels.py	\
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
	         $(SPHINX_V)

ALLSPHINXOPTS  = $(_SPHINXOPTS) \
	         -D version="$(VERSION)" \
	         -D today="$(RELEASE_DATE)" \
	         -D release="$(VERSION)" \
	         $(SPHINXOPTS) \
	         $(srcdir)

man_SPHINXOPTS = $(_SPHINXOPTS) \
	         -D version="@""VERSION@" \
	         -D today="@""RELEASE_DATE@" \
	         -D release="@""VERSION@" \
	         -D extensions="ignore_panels" \
	         $(SPHINXOPTS) \
	         $(srcdir)

.PHONY: html-local singlehtml pdf-local epub man install-html-local install-singlehtml install-pdf-local install-epub

man_MANS =

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

man/knot.conf.5:	man/knot.conf.5in
man/knotc.8:		man/knotc.8in
man/knotd.8:		man/knotd.8in
man/kcatalogprint.8:	man/kcatalogprint.8in
man/keymgr.8:		man/keymgr.8in
man/kjournalprint.8:	man/kjournalprint.8in
man/kdig.1:		man/kdig.1in
man/khost.1:		man/khost.1in
man/knsupdate.1:	man/knsupdate.1in
man/knsec3hash.1:	man/knsec3hash.1in
man/kzonecheck.1:	man/kzonecheck.1in
man/kzonesign.1:	man/kzonesign.1in
man/kxdpgun.8:		man/kxdpgun.8in

man_SUBST = $(AM_V_GEN)mkdir -p man; \
            sed -e 's,[@]VERSION@,$(VERSION),' \
                -e 's,[@]RELEASE_DATE@,$(RELEASE_DATE),' \
                -e 's,[@]config_dir@,$(config_dir),' \
                -e 's,[@]storage_dir@,$(storage_dir),' \
                -e 's,[@]run_dir@,$(run_dir),' \
                -e 's,[@]conf_mapsize@,$(conf_mapsize),' \
            $< > $@

.1in.1:
	$(man_SUBST)

.5in.5:
	$(man_SUBST)

.8in.8:
	$(man_SUBST)

if HAVE_DOCS

if HAVE_SPHINXBUILD
html-local:
	$(AM_V_SPHINX)$(SPHINXBUILD) -b html -d $(SPHINXBUILDDIR)/doctrees $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/html
	@echo "The HTML documentation has been built in $(SPHINXBUILDDIR)/html/"

install-html-local:
	$(INSTALL) -d $(DESTDIR)/$(docdir) $(DESTDIR)/$(docdir)/_static $(DESTDIR)/$(docdir)/_sources
	$(INSTALL) -D $(SPHINXBUILDDIR)/html/*.html $(DESTDIR)/$(docdir)/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/html/_sources/* $(DESTDIR)/$(docdir)/_sources/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/html/_static/* $(DESTDIR)/$(docdir)/_static/

singlehtml:
	$(AM_V_SPHINX)$(SPHINXBUILD) -b singlehtml -d $(SPHINXBUILDDIR)/doctrees $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/singlehtml
	@echo "The single HTML documentation has been built in $(SPHINXBUILDDIR)/singlehtml/"

install-singlehtml: singlehtml
	$(INSTALL) -d $(DESTDIR)/$(docdir) $(DESTDIR)/$(docdir)/_static
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/singlehtml/*.html $(DESTDIR)/$(docdir)/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/singlehtml/_static/* $(DESTDIR)/$(docdir)/_static/

epub:
	$(AM_V_SPHINX)$(SPHINXBUILD) -b epub -A today=$(RELEASE_DATE) -d $(SPHINXBUILDDIR)/doctrees $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/epub
	@echo "The EPUB documentation has been built in $(SPHINXBUILDDIR)/epub/"

install-epub:
	$(INSTALL) -d $(DESTDIR)/$(docdir)
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/epub/KnotDNS.epub $(DESTDIR)/$(docdir)/

if HAVE_PDFLATEX
pdf-local:
	$(AM_V_SPHINX)$(SPHINXBUILD) -b latex -d $(SPHINXBUILDDIR)/doctrees $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/latex
	$(MAKE) -C $(SPHINXBUILDDIR)/latex all-pdf
	@echo "The PDF documentation has been built in $(SPHINXBUILDDIR)/latex/"

install-pdf-local:
	$(INSTALL) -d $(DESTDIR)/$(docdir)
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/latex/KnotDNS.pdf $(DESTDIR)/$(docdir)/

else
pdf-local install-pdf-local:
	@echo "Install 'pdflatex' and re-run configure to be able to generate PDF documentation!"
endif # HAVE_PDFLATEX

.NOTPARALLEL: man
man: $(man_MANS)
$(MANPAGES_IN): $(MANPAGES_RST)
	$(AM_V_SPHINX)$(SPHINXBUILD) -b man -d $(SPHINXBUILDDIR)/doctrees $(man_SPHINXOPTS) $(SPHINXBUILDDIR)/man
	@mkdir -p $(srcdir)/man
	@for f in $(SPHINXBUILDDIR)/man/*; do \
	  sed -e '/^\.TP$$/ {' -e 'n' -e 's/^\.B //' -e '}' "$$f" > "$(srcdir)/man/$$(basename $$f)in"; \
	done

else
html-local singlehtml pdf-local epub man install-html-local install-singlehtml install-pdf-local install-epub:
	@echo "Install 'sphinx-build' and re-run configure to be able to generate documentation!"
endif # HAVE_SPHINXBUILD

endif # HAVE_DOCS

clean-local:
	-rm -rf $(SPHINXBUILDDIR)
	-rm -f man/*.1 man/*.5 man/*.8
