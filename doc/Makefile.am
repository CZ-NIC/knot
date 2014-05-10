SPHINXBUILDDIR = _build
ALLSPHINXOPTS  = -n -d $(SPHINXBUILDDIR)/doctrees -D latex_paper_size=a4 $(SPHINXOPTS) .

.PHONY: help html dirhtml singlehtml pdf info doctest

if HAVE_SPHINXBUILD
html:
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(SPHINXBUILDDIR)/html."

dirhtml:
	$(SPHINXBUILD) -b dirhtml $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/dirhtml
	@echo
	@echo "Build finished. The HTML pages are in $(SPHINXBUILDDIR)/dirhtml."

singlehtml:
	$(SPHINXBUILD) -b singlehtml $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/singlehtml
	@echo
	@echo "Build finished. The HTML page is in $(SPHINXBUILDDIR)/singlehtml."

if HAVE_PDFLATEX
pdf:
	$(SPHINXBUILD) -b latex $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/latex
	@echo "Running LaTeX files through pdflatex..."
	$(MAKE) -C $(SPHINXBUILDDIR)/latex all-pdf
	@echo "pdflatex finished; the PDF files are in $(SPHINXBUILDDIR)/latex."
else
pdf:
	@echo "You need to install pdflatex and re-run configure to be"
	@echo "able to generate PDF documentation."
endif

if HAVE_MAKEINFO
info:
	$(SPHINXBUILD) -b texinfo $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/texinfo
	@echo "Running Texinfo files through makeinfo..."
	make -C $(SPHINXBUILDDIR)/texinfo info
	@echo "makeinfo finished; the Info files are in $(SPHINXBUILDDIR)/texinfo."
else
	@echo "You need to install GNU Texinfo and re-run configure to be"
	@echo "able to generate info pages."
endif

doctest:
	$(SPHINXBUILD) -b doctest $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/doctest
	@echo "Testing of doctests in the sources finished, look at the " \
	      "results in $(SPHINXBUILDDIR)/doctest/output.txt."

else
html pdf info doctest:
	@echo "Please install sphinx (python-sphinx) to generate Knot DNS documentation."
endif

clean-local:
	-rm -rf _build
