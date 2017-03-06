edit = sed \
	-e 's|@version[@]|$(PACKAGE_VERSION)|g' \
	-e 's|@package[@]|$(PACKAGE_NAME)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@prefix[@]|$(prefix)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@config_dir[@]|$(config_dir)|g' \
	-e 's|@storage_dir[@]|$(storage_dir)|g' \
	-e 's|@run_dir[@]|$(run_dir)|g'

knot.sample.conf: knot.sample.conf.in
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	mv $@.tmp $@

EXTRA_DIST = knot.sample.conf.in example.com.zone

if HAVE_DAEMON

install-data-local: knot.sample.conf
	if [ \! -f $(DESTDIR)/$(config_dir)/knot.sample.conf ]; then \
	  $(INSTALL) -d $(DESTDIR)/$(config_dir); \
	  $(INSTALL_DATA) knot.sample.conf $(srcdir)/example.com.zone $(DESTDIR)/$(config_dir); \
	fi
uninstall-local:
	-rm -rf $(DESTDIR)/$(config_dir)/knot.sample.conf \
	        $(DESTDIR)/$(config_dir)/example.com.zone

endif # HAVE_DAEMON

clean-local:
	rm -f knot.sample.conf
