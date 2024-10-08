lib_LTLIBRARIES += libdnssec.la
pkgconfig_DATA  += libdnssec.pc

libdnssec_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(gnutls_CFLAGS)
libdnssec_la_LDFLAGS  = $(AM_LDFLAGS) $(libdnssec_VERSION_INFO) $(LDFLAG_EXCLUDE_LIBS)
libdnssec_la_LIBADD   = $(libcontrib_LIBS) $(gnutls_LIBS)
if ENABLE_PKCS11
libdnssec_la_LIBADD  += $(pthread_LIBS)
endif

EXTRA_DIST += \
	libdnssec/sample_keys.h

include_libdnssecdir = $(includedir)/libdnssec
include_libdnssec_HEADERS = \
	libdnssec/binary.h			\
	libdnssec/crypto.h			\
	libdnssec/digest.h			\
	libdnssec/dnssec.h			\
	libdnssec/error.h			\
	libdnssec/key.h				\
	libdnssec/keyid.h			\
	libdnssec/keystore.h			\
	libdnssec/keytag.h			\
	libdnssec/nsec.h			\
	libdnssec/pem.h				\
	libdnssec/random.h			\
	libdnssec/sign.h			\
	libdnssec/tsig.h			\
	libdnssec/version.h

libdnssec_la_SOURCES = \
	libdnssec/binary.c			\
	libdnssec/crypto.c			\
	libdnssec/digest.c			\
	libdnssec/error.c			\
	libdnssec/key/algorithm.c		\
	libdnssec/key/algorithm.h		\
	libdnssec/key/convert.c			\
	libdnssec/key/convert.h			\
	libdnssec/key/dnskey.c			\
	libdnssec/key/dnskey.h			\
	libdnssec/key/ds.c			\
	libdnssec/key/internal.h		\
	libdnssec/key/key.c			\
	libdnssec/key/keytag.c			\
	libdnssec/key/privkey.c			\
	libdnssec/key/privkey.h			\
	libdnssec/key/simple.c			\
	libdnssec/keyid.c			\
	libdnssec/keystore/internal.h		\
	libdnssec/keystore/keystore.c		\
	libdnssec/keystore/pkcs11.c		\
	libdnssec/keystore/pkcs8.c		\
	libdnssec/nsec/bitmap.c			\
	libdnssec/nsec/hash.c			\
	libdnssec/nsec/nsec.c			\
	libdnssec/p11/p11.c			\
	libdnssec/p11/p11.h			\
	libdnssec/pem.c				\
	libdnssec/random.c			\
	libdnssec/shared/bignum.c		\
	libdnssec/shared/bignum.h		\
	libdnssec/shared/binary_wire.h		\
	libdnssec/shared/dname.c		\
	libdnssec/shared/dname.h		\
	libdnssec/shared/keyid_gnutls.c		\
	libdnssec/shared/keyid_gnutls.h		\
	libdnssec/shared/shared.h		\
	libdnssec/sign/der.c			\
	libdnssec/sign/der.h			\
	libdnssec/sign/sign.c			\
	libdnssec/tsig.c
