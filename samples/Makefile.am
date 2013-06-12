edit = sed \
	-e 's|@version[@]|$(PACKAGE_VERSION)|g' \
	-e 's|@package[@]|$(PACKAGE_NAME)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@prefix[@]|$(prefix)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g'

knot.sample.conf: knot.sample.conf.in
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	mv $@.tmp $@

EXTRA_DIST = knot.sample.conf.in knot.full.conf knot.keys.conf example.com.zone

install-data-local: knot.sample.conf
	[ -d $(DESTDIR)/$(sysconfdir) ] || \
	  $(INSTALL) -d $(DESTDIR)/$(sysconfdir)
	[ -f $(DESTDIR)/$(sysconfdir)/knot.sample.conf ] || \
	  $(INSTALL_DATA) knot.sample.conf $(srcdir)/example.com.zone $(DESTDIR)/$(sysconfdir)

uninstall-local:
	[ -f $(DESTDIR)/$(sysconfdir)/knot.sample.conf ] && \
	  rm -f $(DESTDIR)/$(sysconfdir)/knot.sample.conf
	[ -f $(DESTDIR)/$(sysconfdir)/example.com.zone ] && \
	  rm -f $(DESTDIR)/$(sysconfdir)/example.com.zone

clean-local:
	rm -f knot.sample.conf
