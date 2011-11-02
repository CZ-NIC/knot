edit = sed \
	-e 's|@version[@]|$(PACKAGE_VERSION)|g' \
	-e 's|@package[@]|$(PACKAGE_NAME)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@prefix[@]|$(prefix)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g'

knot.sample.conf: Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	mv $@.tmp $@

knot.sample.conf: knot.sample.conf.in

install-data-local: knot.sample.conf
	[ -d $(DESTDIR)/$(sysconfdir) ] || \
	  $(INSTALL) -d $(DESTDIR)/$(sysconfdir)
	[ -f $(DESTDIR)/$(sysconfdir)/knot.sample.conf ] || \
	  $(INSTALL_DATA) knot.sample.conf example.com.zone $(DESTDIR)/$(sysconfdir)

clean-local:
	rm -f knot.sample.conf
