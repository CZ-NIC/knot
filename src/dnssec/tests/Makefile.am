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
	shared_bignum	\
	shared_dname	\
	shared_wire	\
	tsig

keystore_pkcs11_CPPFLAGS = $(AM_CPPFLAGS) -DLIBDIR='"$(libdir)"'

check-compile: $(check_PROGRAMS)

AM_V_RUNTESTS = $(am__v_RUNTESTS_@AM_V@)
am__v_RUNTESTS_ = $(am__v_RUNTESTS_@AM_DEFAULT_V@)
am__v_RUNTESTS_0 =
am__v_RUNTESTS_1 = RET=$$?; if [ "$$RET" != "0" ]; then cat "$(builddir)/runtests.log"; exit $$RET; fi
check-local: $(check_PROGRAMS)
	$(top_builddir)/libtap/runtests -s $(srcdir) \
					-b $(builddir) \
					-L $(builddir)/runtests.log \
					$(check_PROGRAMS); \
	$(AM_V_RUNTESTS)
