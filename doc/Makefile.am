XMLTO=@XMLTO@
XMLTO_FLAGS=--skip-validation

XML_SOURCES=configuration.xml \
	    installation.xml \
	    introduction.xml \
	    migration.xml \
	    reference.xml \
	    resources.xml \
	    security.xml \
	    troubleshooting.xml

if build_documentation

htmldir = $(prefix)/share/doc/@PACKAGE@
dist_html_DATA = @PACKAGE@.html

@PACKAGE@.html: @PACKAGE@.xml $(XML_SOURCES)
	$(XMLTO) $(XMLTO_FLAGS) html-nochunks @PACKAGE@.xml

fi
