AM_CPPFLAGS = \
	-I$(top_srcdir)/libtap \
	-I$(srcdir)/../shared \
	-I$(srcdir)/../lib \
	-I$(srcdir)/../lib/dnssec

AM_LDFLAGS = \
	-static

LDADD = \
	$(top_builddir)/libtap/libtap.a \
	$(builddir)/../libdnssec.la

check_PROGRAMS = \
	binary		\
	crypto		\
	key		\
	key_algorithm	\
	key_keyid	\
	key_keytag	\
	keystore_pkcs8	\
	keystore_pkcs8_dir \
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
