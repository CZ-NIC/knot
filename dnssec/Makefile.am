SUBDIRS = . tests

AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h

noinst_LTLIBRARIES = lib.la
lib_LTLIBRARIES = libdnssec.la

lib_la_CFLAGS = \
	$(AM_CFLAGS) $(gnutls_CFLAGS) \
	-fvisibility=default \
	-Ilib -Ilib/dnssec

lib_la_LDFLAGS = \
	$(gnutls_LIBS)

libdnssec_la_CFLAGS = \
	$(lib_la_CFLAGS) \
	-fvisibility=default

libdnssec_la_LDFLAGS = \
	$(lib_la_LDFLAGS) \
	-export-symbols-regex '^dnssec_' \
	-version-info 0:1:0

libdnssec_la_LIBADD = lib.la

libdnssec_la_SOURCES =

lib_la_SOURCES = \
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
