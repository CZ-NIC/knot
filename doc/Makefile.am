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
	man_kdig.rst		\
	man_keymgr.rst		\
	man_khost.rst		\
	man_knot1to2.rst	\
	man_knotc.rst		\
	man_knotd.rst		\
	man_knsec3hash.rst	\
	man_knsupdate.rst	\
	\
	logo.eps		\
	logo.png

SPHINXBUILDDIR = _build
ALLSPHINXOPTS  = -n -D latex_paper_size=a4 $(SPHINXOPTS) .

.PHONY: html-local singlehtml pdf-local info-local man install-html-local install-singlehtml install-pdf-local install-info-local

MANPAGES =
MANPAGES_IN =

if HAVE_DAEMON
MANPAGES += man/knot.conf.5 man/knotc.8 man/knotd.8
MANPAGES_IN += reference.rst man_knotc.rst man_knotd.rst
endif # HAVE_DAEMON

if HAVE_UTILS
MANPAGES += man/kdig.1 man/khost.1 man/knsupdate.1 man/knot1to2.1 man/knsec3hash.1 man/keymgr.8
MANPAGES_IN += man_kdig.rst man_khost.rst man_knsupdate.rst man_knot1to2.rst man_knsec3hash.rst man_keymgr.rst 
endif # HAVE_UTILS

dist_man_MANS = $(MANPAGES)

if HAVE_DOCS

if HAVE_SPHINXBUILD
html-local:
	$(SPHINXBUILD) -b html -d $(SPHINXBUILDDIR)/doctrees-html $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(SPHINXBUILDDIR)/html."

install-html-local:
	$(INSTALL) -d $(DESTDIR)/$(docdir) $(DESTDIR)/$(docdir)/_static $(DESTDIR)/$(docdir)/_sources
	$(INSTALL) -D $(SPHINXBUILDDIR)/html/*.html $(DESTDIR)/$(docdir)/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/html/_sources/* $(DESTDIR)/$(docdir)/_sources/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/html/_static/* $(DESTDIR)/$(docdir)/_static/

singlehtml:
	$(SPHINXBUILD) -b singlehtml -d $(SPHINXBUILDDIR)/doctrees-singlehtml $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/singlehtml
	@echo
	@echo "Build finished. The HTML page is in $(SPHINXBUILDDIR)/singlehtml."

install-singlehtml: singlehtml
	$(INSTALL) -d $(DESTDIR)/$(docdir) $(DESTDIR)/$(docdir)/_static
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/singlehtml/*.html $(DESTDIR)/$(docdir)/
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/singlehtml/_static/* $(DESTDIR)/$(docdir)/_static/

if HAVE_PDFLATEX
pdf-local:
	$(SPHINXBUILD) -b latex -d $(SPHINXBUILDDIR)/doctrees-latex $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/latex
	$(MAKE) -C $(SPHINXBUILDDIR)/latex all-pdf
	@echo
	@echo "Build finished. The PDF files are in $(SPHINXBUILDDIR)/latex."

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
	@echo "Build finished. The Info files are in $(SPHINXBUILDDIR)/texinfo."

install-info-local:
	$(INSTALL) -d $(DESTDIR)/$(infodir)
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/texinfo/knot.info $(DESTDIR)/$(infodir)/

else
info-local install-info-local:
	@echo "You need to install GNU Texinfo and re-run configure to be"
	@echo "able to generate info pages."
endif

man: $(MANPAGES)
$(MANPAGES): $(MANPAGES_IN) ../configure.ac
	$(SPHINXBUILD) -b man -D version="@VERSION@" -D today="@RELEASE_DATE@" -d $(SPHINXBUILDDIR)/doctrees-man $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/man
	mkdir -p man
	for f in $(SPHINXBUILDDIR)/man/*; do \
	  sed -e '/^.TP$$/{n;s/^.B //}' "$$f" > "man/$$(basename $$f)"; \
	done
	@echo
	@echo "Build finished. The man pages are in man/."

else
html-local singlehtml pdf-local info-local man install-html-local install-singlehtml install-pdf-local install-info-local:
	@echo "Please install sphinx (python-sphinx) to generate Knot DNS documentation."
endif # HAVE_SPHINXBUILD

endif # HAVE_DOCS

clean-local:
	-rm -rf _build
