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

EXTRA_DIST = knot.sample.conf.in example.com.zone keymgr-completion.sh keymgr-completion.zsh

if HAVE_DAEMON

install-data-local: knot.sample.conf
	[ -d $(DESTDIR)/$(config_dir) ] || \
	  $(INSTALL) -d $(DESTDIR)/$(config_dir)
	[ -f $(DESTDIR)/$(config_dir)/knot.sample.conf ] || \
	  $(INSTALL_DATA) knot.sample.conf $(srcdir)/example.com.zone $(DESTDIR)/$(config_dir)
	[ -d $(DESTDIR)/$(sysconfdir)/bash_completion.d ] ||
	  $(INSTALL) -d $(DESTDIR)/$(sysconfdir)/bash_completion.d
	[ -f $(DESTDIR)/$(sysconfdir)/keymgr-completion.sh ] || \
	  $(INSTALL_DATA) keymgr-completion.sh $(DESTDIR)/$(sysconfdir)/bash_completion.d/keymgr
	[ -d $(DESTDIR)/$(sysconfdir)/bash_completion.d ] ||
	  $(INSTALL) -d $(DESTDIR)/$(sysconfdir)/bash_completion.d
	[ -f $(DESTDIR)/$(sysconfdir)/keymgr-completion.sh ] || \
	  $(INSTALL_DATA) keymgr-completion.sh $(DESTDIR)/$(sysconfdir)/bash_completion.d/

uninstall-local:
	[ -f $(DESTDIR)/$(config_dir)/knot.sample.conf ] && \
	  rm -f $(DESTDIR)/$(config_dir)/knot.sample.conf
	[ -f $(DESTDIR)/$(config_dir)/example.com.zone ] && \
	  rm -f $(DESTDIR)/$(config_dir)/example.com.zone
	[ -f $(DESTDIR)/$(sysconfdir)/keymgr-completion.sh ] && \
	  rm -f $(DESTDIR)/$(sysconfdir)/bash_completion.d/keymgr

endif # HAVE_DAEMON

clean-local:
	rm -f knot.sample.conf
