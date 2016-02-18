AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(top_srcdir)/libtap \
	-I$(srcdir)/../shared \
	-I$(srcdir)/../lib \
	-I$(srcdir)/../lib/dnssec \
	$(gnutls_CFLAGS)

AM_LDFLAGS = \
	-static

LDADD = \
	$(top_builddir)/libtap/libtap.la \
	$(builddir)/../libdnssec.la

CLEANFILES = runtests.log

EXTRA_DIST = sample_keys.h

check_PROGRAMS = \
	binary		\
	crypto		\
	event_keystate	\
	kasp_dir_escape	\
	kasp_dir_file	\
	kasp_store	\
	key		\
	key_algorithm	\
	key_ds		\
	keyid		\
	keystore_pkcs11 \
	keystore_pkcs8	\
	keystore_pkcs8_dir \
	keytag		\
	list		\
	nsec_bitmap	\
	nsec_hash	\
	random		\
	sign		\
	sign_der	\
	shared_base32hex \
	shared_bignum	\
	shared_dname	\
	shared_strtonum	\
	shared_timestamp \
	shared_wire	\
	tsig

keystore_pkcs11_CPPFLAGS = $(AM_CPPFLAGS) -DLIBDIR='"$(libdir)"'

check-compile-local: $(check_PROGRAMS)

check-local: $(check_PROGRAMS)
	$(top_builddir)/libtap/runtests -s $(srcdir) \
					-b $(builddir) \
					-L $(builddir)/runtests.log \
					$(check_PROGRAMS)
