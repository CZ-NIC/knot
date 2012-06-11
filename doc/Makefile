XML_SOURCES=knot.xml configuration.xml installation.xml introduction.xml knot.xml migration.xml reference.xml resources.xml security.xml troubleshooting.xml

all: knot.html knot.pdf

knot.pdf: $(XML_SOURCES)
	xmlto --with-dblatex --skip-validation pdf knot.xml

knot.html: $(XML_SOURCES)
	xmlto --skip-validation html-nochunks knot.xml

clean:
	rm -f *.proc *.pdf *.html
