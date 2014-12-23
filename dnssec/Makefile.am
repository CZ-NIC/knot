SUBDIRS = . utils tests man

AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(srcdir)/shared \
	-I$(srcdir)/lib \
	-I$(srcdir)/lib/dnssec \
	$(CODE_COVERAGE_CFLAGS) \
	$(gnutls_CFLAGS) \
	$(jannson_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS)

noinst_LTLIBRARIES = libshared.la
lib_LTLIBRARIES = libdnssec.la

libshared_la_CPPFLAGS = \
	$(AM_CPPFLAGS)

libshared_la_SOURCES = \
	shared/base32hex.c \
	shared/base32hex.h \
	shared/dname.c \
	shared/dname.h \
	shared/fs.c \
	shared/fs.h \
	shared/hex.c \
	shared/hex.h \
	shared/hex_gnutls.c \
	shared/hex_gnutls.h \
	shared/path.c \
	shared/path.h \
	shared/pem.c \
	shared/pem.h \
	shared/shared.h \
	shared/strtonum.h \
	shared/wire.h

libdnssec_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-fvisibility=hidden

libdnssec_la_LDFLAGS = \
	$(gnutls_LIBS) \
	$(jansson_LIBS) \
	-version-info 0:1:0

libdnssec_la_LIBADD = \
	libshared.la

include_dnssecdir=$(includedir)/dnssec
include_dnssec_HEADERS = \
	lib/dnssec/binary.h \
	lib/dnssec/crypto.h \
	lib/dnssec/error.h \
	lib/dnssec/kasp.h \
	lib/dnssec/key.h \
	lib/dnssec/keyid.h \
	lib/dnssec/keystore.h \
	lib/dnssec/keytag.h \
	lib/dnssec/list.h \
	lib/dnssec/nsec.h \
	lib/dnssec/random.h \
	lib/dnssec/sign.h \
	lib/dnssec/tsig.h

libdnssec_la_SOURCES = \
	lib/binary.c \
	lib/crypto.c \
	lib/error.c \
	lib/kasp/dir/dir.c \
	lib/kasp/dir/escape.c \
	lib/kasp/dir/escape.h \
	lib/kasp/dir/file.c \
	lib/kasp/dir/file.h \
	lib/kasp/dir/json.c \
	lib/kasp/dir/json.h \
	lib/kasp/dir/zone.c \
	lib/kasp/dir/zone.h \
	lib/kasp/dir/policy.c \
	lib/kasp/dir/policy.h \
	lib/kasp/internal.h \
	lib/kasp/kasp.c \
	lib/kasp/zone.c \
	lib/kasp/policy.c \
	lib/kasp/zone.h \
	lib/key/algorithm.c \
	lib/key/algorithm.h \
	lib/key/convert.c \
	lib/key/convert.h \
	lib/key/dnskey.c \
	lib/key/dnskey.h \
	lib/key/ds.c \
	lib/key/internal.h \
	lib/key/key.c \
	lib/key/keytag.c \
	lib/key/privkey.c \
	lib/key/privkey.h \
	lib/key/simple.c \
	lib/keyid.c \
	lib/keystore/internal.h \
	lib/keystore/keystore.c \
	lib/keystore/pkcs11.c \
	lib/keystore/pkcs8.c \
	lib/keystore/pkcs8_dir.c \
	lib/list/list.c \
	lib/list/ucw_clists.h \
	lib/nsec/bitmap.c \
	lib/nsec/hash.c \
	lib/random.c \
	lib/sign/der.c \
	lib/sign/der.h \
	lib/sign/sign.c \
	lib/tsig.c
