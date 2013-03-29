MANPAGES = knot.conf.5 knotc.8 knotd.8 kdig.8 khost.8 knsupdate.8

.5in.5:
	$(SED) 's;\@VERSION\@;@VERSION@;g' $< > $@
.8in.8:
	$(SED) 's;\@VERSION\@;@VERSION@;g' $< > $@

dist_man_MANS = $(MANPAGES)
CLEANFILES = $(MANPAGES)
