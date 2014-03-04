AM_CPPFLAGS = -I$(top_srcdir)/libtap -I../src
LDADD = $(top_builddir)/libtap/libtap.a \
	../libdnssec.la

check_PROGRAMS = \
	binary		\
	key		\
	key_pubkey	\
	sign

check-compile-only: $(check_PROGRAMS)

check-local: $(check_PROGRAMS)
	$(top_builddir)/libtap/runtests -s $(top_srcdir)/tests \
					-b $(top_builddir)/tests \
					$(check_PROGRAMS)
