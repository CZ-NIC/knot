sysconf_DATA = knotd.conf example.com.zone

edit = sed \
	-e 's|@version[@]|$(PACKAGE_VERSION)|g' \
	-e 's|@package[@]|$(PACKAGE_NAME)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@prefix[@]|$(prefix)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g'

knotd.conf: Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	mv $@.tmp $@

knotd.conf: knotd.conf.in

clean-local:
	rm -f knotd.conf
