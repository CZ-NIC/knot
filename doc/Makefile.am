MANPAGES_IN = \
	man/knot.conf.5in	\
	man/knotc.8in		\
	man/knotd.8in		\
	man/keymgr.8in		\
	man/pykeymgr.8in	\
	man/kdig.1in		\
	man/khost.1in		\
	man/kjournalprint.1in	\
	man/knsupdate.1in	\
	man/knsec3hash.1in	\
	man/kzonecheck.1in

MANPAGES_RST = \
	man_knotc.rst		\
	man_knotd.rst		\
	man_keymgr.rst		\
	man_pykeymgr.rst	\
	man_kdig.rst		\
	man_khost.rst		\
	man_kjournalprint.rst	\
	man_knsupdate.rst	\
	man_knsec3hash.rst	\
	man_kzonecheck.rst

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
	logo.eps		\
	logo.png

SPHINX_V = $(SPHINX_V_@AM_V@)
SPHINX_V_ = $(SPHINX_V_@AM_DEFAULT_V@)
SPHINX_V_0 = -q
SPHINX_V_1 = -n

AM_V_SPHINX = $(AM_V_SPHINX_@AM_V@)
AM_V_SPHINX_ = $(AM_V_SPHINX_@AM_DEFAULT_V@)
AM_V_SPHINX_0 = @echo "  SPHINX   $@";

AM_V_ECHO = @sh -c 'if $(AM_V_P); then echo $$1; fi' --

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
	         $(SPHINXOPTS) \
	         $(srcdir)

.PHONY: html-local singlehtml pdf-local info-local man install-html-local install-singlehtml install-pdf-local install-info-local

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
	man/keymgr.8		\
	man/pykeymgr.8		\
	man/kjournalprint.1	\
	man/kzonecheck.1
endif # HAVE_DAEMON

man_MANS += \
	man/kdig.1		\
	man/khost.1		\
	man/knsupdate.1		\
	man/knsec3hash.1
endif # HAVE_UTILS

man/knot.conf.5:	man/knot.conf.5in
man/knotc.8:		man/knotc.8in
man/knotd.8:		man/knotd.8in
man/keymgr.8:		man/keymgr.8in
man/pykeymgr.8:		man/pykeymgr.8in
man/kdig.1:		man/kdig.1in
man/khost.1:		man/khost.1in
man/kjournalprint.1:	man/kjournalprint.1in
man/knsupdate.1:	man/knsupdate.1in
man/knsec3hash.1:	man/knsec3hash.1in
man/kzonecheck.1:	man/kzonecheck.1in

man_SUBST = $(AM_V_GEN)mkdir -p man; sed -e 's,[@]VERSION@,$(VERSION),' -e 's,[@]RELEASE_DATE@,$(RELEASE_DATE),' $< > $@

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
	$(AM_V_ECHO)
	$(AM_V_ECHO) "Build finished. The HTML pages are in $(SPHINXBUILDDIR)/html/."

install-html-local:
	$(INSTALL) -d $(DESTDIR)/$(docdir) $(DESTDIR)/$(docdir)/_static $(DESTDIR)/$(docdir)/_sources
	$(INSTALL) -D $(SPHINXBUILDDIR)/html/*.html $(DESTDIR)/$(docdir)/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/html/_sources/* $(DESTDIR)/$(docdir)/_sources/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/html/_static/* $(DESTDIR)/$(docdir)/_static/

singlehtml:
	$(AM_V_SPHINX)$(SPHINXBUILD) -b singlehtml -d $(SPHINXBUILDDIR)/doctrees $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/singlehtml
	$(AM_V_ECHO)
	$(AM_V_ECHO) "Build finished. The HTML page is in $(SPHINXBUILDDIR)/singlehtml/."

install-singlehtml: singlehtml
	$(INSTALL) -d $(DESTDIR)/$(docdir) $(DESTDIR)/$(docdir)/_static
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/singlehtml/*.html $(DESTDIR)/$(docdir)/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/singlehtml/_static/* $(DESTDIR)/$(docdir)/_static/

if HAVE_PDFLATEX
pdf-local:
	$(AM_V_SPHINX)$(SPHINXBUILD) -b latex -d $(SPHINXBUILDDIR)/doctrees $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/latex
	$(MAKE) -C $(SPHINXBUILDDIR)/latex all-pdf
	$(AM_V_ECHO)
	$(AM_V_ECHO) "Build finished. The PDF file is in $(SPHINXBUILDDIR)/latex/."

install-pdf-local:
	$(INSTALL) -d $(DESTDIR)/$(docdir)
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/latex/knot.pdf $(DESTDIR)/$(docdir)/

else
pdf-local install-pdf-local:
	$(AM_V_ECHO) "You need to install pdflatex and re-run configure to be"
	$(AM_V_ECHO) "able to generate PDF documentation."
endif

if HAVE_MAKEINFO
info-local:
	$(AM_V_SPHINX)$(SPHINXBUILD) -b texinfo -d $(SPHINXBUILDDIR)/doctrees $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/texinfo
	$(MAKE) -C $(SPHINXBUILDDIR)/texinfo info
	$(AM_V_ECHO)
	$(AM_V_ECHO) "Build finished. The Info file is in $(SPHINXBUILDDIR)/texinfo/."

install-info-local:
	$(INSTALL) -d $(DESTDIR)/$(infodir)
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/texinfo/knot.info $(DESTDIR)/$(infodir)/

else
info-local install-info-local:
	$(AM_V_ECHO) "You need to install GNU Texinfo and re-run configure to be"
	$(AM_V_ECHO) "able to generate info pages."
endif

.NOTPARALLEL: man
man: $(man_MANS)
$(MANPAGES_IN): $(MANPAGES_RST)
	$(AM_V_SPHINX)$(SPHINXBUILD) -b man -d $(SPHINXBUILDDIR)/doctrees $(man_SPHINXOPTS) $(SPHINXBUILDDIR)/man
	@mkdir -p $(srcdir)/man
	@for f in $(SPHINXBUILDDIR)/man/*; do \
	  sed -e '/^\.TP$$/ {' -e 'n' -e 's/^\.B //' -e '}' "$$f" > "$(srcdir)/man/$$(basename $$f)in"; \
	done
	$(AM_V_ECHO)
	$(AM_V_ECHO) "Build finished. The man pages are in man/."

else
html-local singlehtml pdf-local info-local man install-html-local install-singlehtml install-pdf-local install-info-local:
	$(AM_V_ECHO) "Please install sphinx (python-sphinx) to generate Knot DNS documentation."
endif # HAVE_SPHINXBUILD

endif # HAVE_DOCS

clean-local:
	-rm -rf $(SPHINXBUILDDIR)
	-rm -f man/*.1 man/*.5 man/*.8
