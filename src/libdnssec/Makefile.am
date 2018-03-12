AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(top_srcdir)/src
	$(gnutls_CFLAGS)

noinst_LTLIBRARIES = libshared.la
lib_LTLIBRARIES = libdnssec.la

libshared_la_CPPFLAGS = \
	$(AM_CPPFLAGS)

libshared_la_SOURCES = \
	shared/bignum.c \
	shared/bignum.h \
	shared/binary_wire.h \
	shared/dname.c \
	shared/dname.h \
	shared/fs.c \
	shared/fs.h \
	shared/hex.c \
	shared/hex.h \
	shared/keyid_gnutls.c \
	shared/keyid_gnutls.h \
	shared/pem.c \
	shared/pem.h \
	shared/shared.h

libdnssec_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(CFLAG_VISIBILITY)

libdnssec_la_LDFLAGS = \
	$(gnutls_LIBS) \
	$(libdnssec_VERSION_INFO)

libdnssec_la_LIBADD = \
	libshared.la

include_dnssecdir=$(includedir)/dnssec
include_dnssec_HEADERS = \
	binary.h \
	crypto.h \
	dnssec.h \
	error.h \
	key.h \
	keyid.h \
	keystore.h \
	keytag.h \
	list.h \
	nsec.h \
	random.h \
	sign.h \
	tsig.h \
	version.h

libdnssec_la_SOURCES = \
	contrib/vpool.c \
	contrib/vpool.h \
	binary.c \
	crypto.c \
	error.c \
	key/algorithm.c \
	key/algorithm.h \
	key/convert.c \
	key/convert.h \
	key/dnskey.c \
	key/dnskey.h \
	key/ds.c \
	key/internal.h \
	key/key.c \
	key/keytag.c \
	key/privkey.c \
	key/privkey.h \
	key/simple.c \
	keyid.c \
	keystore/internal.h \
	keystore/keystore.c \
	keystore/pkcs11.c \
	keystore/pkcs8.c \
	keystore/pkcs8_dir.c \
	list/list.c \
	list/ucw_clists.h \
	nsec/bitmap.c \
	nsec/hash.c \
	nsec/nsec.c \
	p11/p11.c \
	p11/p11.h \
	random.c \
	sign/der.c \
	sign/der.h \
	sign/sign.c \
	tsig.c

# pkg-config
pkgconfig_DATA = libdnssec.pc
