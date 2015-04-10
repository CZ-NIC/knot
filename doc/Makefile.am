EXTRA_DIST = \
	configuration.rst	\
	index.rst		\
	installation.rst	\
	introduction.rst	\
	migration.rst		\
	reference.rst		\
	requirements.rst	\
	running.rst		\
	troubleshooting.rst	\
	\
	logo.eps		\
	logo.png

SPHINXBUILDDIR = _build
ALLSPHINXOPTS  = -n -d $(SPHINXBUILDDIR)/doctrees -D latex_paper_size=a4 $(SPHINXOPTS) .

.PHONY: html-local singlehtml pdf-local info-local man

if HAVE_DOCS

if HAVE_SPHINXBUILD
html-local:
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(SPHINXBUILDDIR)/html."

singlehtml:
	$(SPHINXBUILD) -b singlehtml $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/singlehtml
	@echo
	@echo "Build finished. The HTML page is in $(SPHINXBUILDDIR)/singlehtml."

if HAVE_PDFLATEX
pdf-local:
	$(SPHINXBUILD) -b latex $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/latex
	@echo "Running LaTeX files through pdflatex..."
	$(MAKE) -C $(SPHINXBUILDDIR)/latex all-pdf
	@echo "pdflatex finished; the PDF files are in $(SPHINXBUILDDIR)/latex."
else
	@echo "You need to install pdflatex and re-run configure to be"
	@echo "able to generate PDF documentation."
endif

if HAVE_MAKEINFO
info-local:
	$(SPHINXBUILD) -b texinfo $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/texinfo
	@echo "Running Texinfo files through makeinfo..."
	make -C $(SPHINXBUILDDIR)/texinfo info
	@echo "makeinfo finished; the Info files are in $(SPHINXBUILDDIR)/texinfo."
else
	@echo "You need to install GNU Texinfo and re-run configure to be"
	@echo "able to generate info pages."
endif

man:
	$(SPHINXBUILD) -b man -D version="__VERSION__" -D today="__DATE__" $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/man
	@echo
	@echo "Build finished. The man pages are in $(SPHINXBUILDDIR)/man."

else
html-local singlehtml pdf-local info-local man:
	@echo "Please install sphinx (python-sphinx) to generate Knot DNS documentation."
endif

endif # HAVE_DOCS

clean-local:
	-rm -rf _build
