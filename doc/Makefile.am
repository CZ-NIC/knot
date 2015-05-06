MANPAGES_IN = man/knot.conf.5in man/knotc.8in man/knotd.8in man/kdig.1in man/khost.1in man/knsupdate.1in man/knot1to2.1in man/knsec3hash.1in man/keymgr.8in
MANPAGES_RST = reference.rst man_knotc.rst man_knotd.rst man_kdig.rst man_khost.rst man_knsupdate.rst man_knot1to2.rst man_knsec3hash.rst man_keymgr.rst

EXTRA_DIST = \
	conf.py		\
	\
	configuration.rst	\
	index.rst		\
	installation.rst	\
	introduction.rst	\
	migration.rst		\
	reference.rst		\
	requirements.rst	\
	running.rst		\
	troubleshooting.rst	\
	utilities.rst		\
	\
	$(MANPAGES_IN)		\
	$(MANPAGES_RST)
	\
	logo.eps		\
	logo.png

SPHINXBUILDDIR = $(builddir)/_build
ALLSPHINXOPTS  = -c $(srcdir) -n -D latex_paper_size=a4 -D version="@""VERSION@" -D today="@""RELEASE_DATE@" -D release="@""VERSION@" $(SPHINXOPTS) $(srcdir)

.PHONY: html-local singlehtml pdf-local info-local man install-html-local install-singlehtml install-pdf-local install-info-local

man_MANS = 

if HAVE_DAEMON
man_MANS += man/knot.conf.5 man/knotc.8 man/knotd.8
endif # HAVE_DAEMON

if HAVE_UTILS
man_MANS += man/kdig.1 man/khost.1 man/knsupdate.1 man/knot1to2.1 man/knsec3hash.1 man/keymgr.8
endif # HAVE_UTILS

man/knot.conf.5: man/knot.conf.5in
man/knotc.8: man/knotc.8in
man/knotd.8: man/knotd.8in
man/kdig.1: man/kdig.1in
man/khost.1: man/khost.1in
man/knsupdate.1: man/knsupdate.1in
man/knot1to2.1: man/knot1to2.1in
man/knsec3hash.1: man/knsec3hash.1in
man/keymgr.8: man/keymgr.8in

man_SUBST = mkdir -p man; sed -e 's,[@]VERSION@,$(VERSION),' -e 's,[@]RELEASE_DATE@,$(RELEASE_DATE),' $< > $@

.1in.1:
	$(man_SUBST)

.5in.5:
	$(man_SUBST)

.8in.8:
	$(man_SUBST)


if HAVE_DOCS

if HAVE_SPHINXBUILD
html-local:
	$(SPHINXBUILD) -b html -d $(SPHINXBUILDDIR)/doctrees-html $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(SPHINXBUILDDIR)/html/."

install-html-local:
	$(INSTALL) -d $(DESTDIR)/$(docdir) $(DESTDIR)/$(docdir)/_static $(DESTDIR)/$(docdir)/_sources
	$(INSTALL) -D $(SPHINXBUILDDIR)/html/*.html $(DESTDIR)/$(docdir)/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/html/_sources/* $(DESTDIR)/$(docdir)/_sources/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/html/_static/* $(DESTDIR)/$(docdir)/_static/

singlehtml:
	$(SPHINXBUILD) -b singlehtml -d $(SPHINXBUILDDIR)/doctrees-singlehtml $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/singlehtml
	@echo
	@echo "Build finished. The HTML page is in $(SPHINXBUILDDIR)/singlehtml/."

install-singlehtml: singlehtml
	$(INSTALL) -d $(DESTDIR)/$(docdir) $(DESTDIR)/$(docdir)/_static
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/singlehtml/*.html $(DESTDIR)/$(docdir)/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/singlehtml/_static/* $(DESTDIR)/$(docdir)/_static/

if HAVE_PDFLATEX
pdf-local:
	$(SPHINXBUILD) -b latex -d $(SPHINXBUILDDIR)/doctrees-latex $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/latex
	$(MAKE) -C $(SPHINXBUILDDIR)/latex all-pdf
	@echo
	@echo "Build finished. The PDF file is in $(SPHINXBUILDDIR)/latex/."

install-pdf-local:
	$(INSTALL) -d $(DESTDIR)/$(docdir)
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/latex/knot.pdf $(DESTDIR)/$(docdir)/

else
pdf-local install-pdf-local:
	@echo "You need to install pdflatex and re-run configure to be"
	@echo "able to generate PDF documentation."
endif

if HAVE_MAKEINFO
info-local:
	$(SPHINXBUILD) -b texinfo -d $(SPHINXBUILDDIR)/doctrees-texinfo $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/texinfo
	$(MAKE) -C $(SPHINXBUILDDIR)/texinfo info
	@echo
	@echo "Build finished. The Info file is in $(SPHINXBUILDDIR)/texinfo/."

install-info-local:
	$(INSTALL) -d $(DESTDIR)/$(infodir)
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/texinfo/knot.info $(DESTDIR)/$(infodir)/

else
info-local install-info-local:
	@echo "You need to install GNU Texinfo and re-run configure to be"
	@echo "able to generate info pages."
endif

man: $(man_MANS)
$(MANPAGES_IN): $(MANPAGES_RST)
	$(SPHINXBUILD) -b man -d $(SPHINXBUILDDIR)/doctrees-man $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/man
	mkdir -p $(srcdir)/man
	for f in $(SPHINXBUILDDIR)/man/*; do \
	  sed -e '/^.TP$$/{n;s/^.B //}' "$$f" > "$(srcdir)/man/$$(basename $$f)in"; \
	done
	@echo
	@echo "Build finished. The man pages are in man/."

else
html-local singlehtml pdf-local info-local man install-html-local install-singlehtml install-pdf-local install-info-local:
	@echo "Please install sphinx (python-sphinx) to generate Knot DNS documentation."
endif # HAVE_SPHINXBUILD

endif # HAVE_DOCS

clean-local:
	-rm -rf $(SPHINXBUILDDIR)
	-rm -f man/*.1 man/*.5 man/*.8
