SUBDIRS = . tests

AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h

lib_LTLIBRARIES = libdnssec.la
noinst_LTLIBRARIES = lib.la

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
	lib/key/ds.c \
	lib/key/internal.h \
	lib/key/key.c \
	lib/key/keyid.c \
	lib/key/keytag.c \
	lib/key/keytag.h \
	lib/key/pubkey.c \
	lib/key/pubkey.h \
	lib/keystore/internal.h \
	lib/keystore/keystore.c \
	lib/keystore/pkcs11.c \
	lib/keystore/pkcs8.c \
	lib/keystore/pkcs8_dir.c \
	lib/nsec/bitmap.c \
	lib/nsec/hash.c \
	lib/random.c \
	lib/shared.h \
	lib/sign/der.c \
	lib/sign/der.h \
	lib/sign/sign.c \
	lib/wire.h

lib_la_CFLAGS  = $(libdnssec_la_CFLAGS) -fvisibility=default
lib_la_LDFLAGS = $(gnutls_LIBS)
lib_la_SOURCES = $(libdnssec_la_SOURCES)
