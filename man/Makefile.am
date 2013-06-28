MANPAGES = knot.conf.5 knotc.8 knotd.8 kdig.1 khost.1 knsupdate.1

.5in.5:
	$(SED) 's;\@VERSION\@;@VERSION@;g' $< > $@
.8in.8:
	$(SED) 's;\@VERSION\@;@VERSION@;g' $< > $@

dist_man_MANS = $(MANPAGES)
CLEANFILES = $(MANPAGES)
