SUBDIRS = . tests

AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h

lib_LTLIBRARIES = libdnssec.la

libdnssec_la_CFLAGS = \
	$(AM_CFLAGS) $(gnutls_CFLAGS) \
	-fvisibility=hidden \
	-Ilib -Ilib/dnssec

libdnssec_la_LDFLAGS = \
	$(gnutls_LIBS) \
	-version-info 0:1:0

libdnssec_la_SOURCES = \
	lib/binary.c \
	lib/crypto.c \
	lib/dnssec/binary.h \
	lib/dnssec/crypto.h \
	lib/dnssec/error.h \
	lib/dnssec/key.h \
	lib/dnssec/keystore.h \
	lib/dnssec/nsec.h \
	lib/dnssec/random.h \
	lib/dnssec/sign.h \
	lib/hex.c \
	lib/hex.h \
	lib/key/algorithm.c \
	lib/key/algorithm.h \
	lib/key/convert.c \
	lib/key/convert.h \
	lib/key/dnskey.c \
	lib/key/dnskey.h \
	lib/key/ds.c \
	lib/key/internal.h \
	lib/key/key.c \
	lib/key/keyid.c \
	lib/key/keyid.h \
	lib/key/keytag.c \
	lib/key/keytag.h \
	lib/key/simple.c \
	lib/keystore/internal.h \
	lib/keystore/keystore.c \
	lib/keystore/pem.c \
	lib/keystore/pem.h \
	lib/keystore/pkcs11.c \
	lib/keystore/pkcs8.c \
	lib/keystore/pkcs8_dir.c \
	lib/keystore/public.c \
	lib/keystore/public.h \
	lib/nsec/bitmap.c \
	lib/nsec/hash.c \
	lib/random.c \
	lib/shared.h \
	lib/sign/der.c \
	lib/sign/der.h \
	lib/sign/sign.c \
	lib/wire.h
