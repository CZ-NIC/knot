MANPAGES = 

if HAVE_DAEMON
MANPAGES += knot.conf.5 knotc.8 knotd.8
endif # HAVE_DAEMON

if HAVE_UTILS
MANPAGES += kdig.1 khost.1 knsupdate.1
endif # HAVE_UTILS

dist_man_MANS = $(MANPAGES)

clean-local:
	-rm *.1 *.5 *.8
