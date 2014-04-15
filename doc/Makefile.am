PAPER         = 
BUILDDIR      = _build

# Internal variables.
PAPEROPT_a4     = -D latex_paper_size=a4
PAPEROPT_letter = -D latex_paper_size=letter
ALLSPHINXOPTS   = -d $(BUILDDIR)/doctrees $(PAPEROPT_$(PAPER)) $(SPHINXOPTS) .

.PHONY: help html dirhtml singlehtml pdf info doctest

if HAVE_SPHINXBUILD
html:
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(BUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."

dirhtml:
	$(SPHINXBUILD) -b dirhtml $(ALLSPHINXOPTS) $(BUILDDIR)/dirhtml
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/dirhtml."

singlehtml:
	$(SPHINXBUILD) -b singlehtml $(ALLSPHINXOPTS) $(BUILDDIR)/singlehtml
	@echo
	@echo "Build finished. The HTML page is in $(BUILDDIR)/singlehtml."

if HAVE_PDFLATEX
pdf:
	$(SPHINXBUILD) -b latex $(ALLSPHINXOPTS) $(BUILDDIR)/latex
	@echo "Running LaTeX files through pdflatex..."
	$(MAKE) -C $(BUILDDIR)/latex all-pdf
	@echo "pdflatex finished; the PDF files are in $(BUILDDIR)/latex."
else
pdf:
	@echo "You need to install pdflatex and re-run configure to be"
	@echo "able to generate PDF documentation."
endif

if HAVE_MAKEINFO
info:
	$(SPHINXBUILD) -b texinfo $(ALLSPHINXOPTS) $(BUILDDIR)/texinfo
	@echo "Running Texinfo files through makeinfo..."
	make -C $(BUILDDIR)/texinfo info
	@echo "makeinfo finished; the Info files are in $(BUILDDIR)/texinfo."
else
	@echo "You need to install GNU Texinfo and re-run configure to be"
	@echo "able to generate info pages."
endif

doctest:
	$(SPHINXBUILD) -b doctest $(ALLSPHINXOPTS) $(BUILDDIR)/doctest
	@echo "Testing of doctests in the sources finished, look at the " \
	      "results in $(BUILDDIR)/doctest/output.txt."

else
html pdf info doctest:
	@echo "Please install sphinx (python-sphinx) to generate Knot DNS documentation."
endif

#info_TEXINFOS = knot.texi
#knot_TEXINFOS = 				\
#		configuration.texi		\
#		indices.texi			\
#		installation.texi		\
#		introduction.texi		\
#		knot.texi			\
#		migration.texi			\
#		reference.texi			\
#		requirements.texi		\
#		running.texi			\
#		security.texi			\
#		synth_record.texi		\
#		troubleshooting.texi		\
#		version.texi
