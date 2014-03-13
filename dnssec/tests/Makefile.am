AM_CPPFLAGS = \
	-I$(top_srcdir)/libtap \
	-I$(srcdir)/../src

LDADD = \
	$(top_builddir)/libtap/libtap.a \
	$(builddir)/../libdnssec.la

check_PROGRAMS = \
	binary		\
	key		\
	key_keytag	\
	key_pubkey	\
	nsec_bitmap	\
	nsec_hash	\
	random		\
	sign		\
	sign_der	\
	wire

check-compile-only: $(check_PROGRAMS)

check-local: $(check_PROGRAMS)
	$(top_builddir)/libtap/runtests -s $(srcdir) \
					-b $(builddir) \
					-L $(builddir)/runtests.log \
					$(check_PROGRAMS) || :
	@echo -e '\033[1;31mWARNING\e[0m: The result of DNSSEC tests is ignored!'
