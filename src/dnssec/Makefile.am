SUBDIRS = . tests

.PHONY: check-compile
check-compile:
	$(MAKE) $(AM_MAKEFLAGS) -C tests $@

AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(srcdir)/shared \
	-I$(srcdir)/lib \
	-I$(srcdir)/lib/dnssec \
	-I$(top_srcdir)/src \
	$(gnutls_CFLAGS) \
	$(jansson_CFLAGS)

noinst_LTLIBRARIES = libshared.la
lib_LTLIBRARIES = libdnssec.la

libshared_la_CPPFLAGS = \
	$(AM_CPPFLAGS)

libshared_la_SOURCES = \
	shared/base32hex.c \
	shared/base32hex.h \
	shared/bignum.c \
	shared/bignum.h \
	shared/dname.c \
	shared/dname.h \
	shared/fs.c \
	shared/fs.h \
	shared/hex.c \
	shared/hex.h \
	shared/keyid_gnutls.c \
	shared/keyid_gnutls.h \
	shared/path.c \
	shared/path.h \
	shared/pem.c \
	shared/pem.h \
	shared/shared.h \
	shared/timestamp.c \
	shared/timestamp.h \
	shared/wire.h

libdnssec_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(CFLAG_VISIBILITY)

libdnssec_la_LDFLAGS = \
	$(gnutls_LIBS) \
	$(jansson_LIBS) \
	$(libdnssec_VERSION_INFO)

libdnssec_la_LIBADD = \
	libshared.la

include_dnssecdir=$(includedir)/dnssec
include_dnssec_HEADERS = \
	lib/dnssec/binary.h \
	lib/dnssec/crypto.h \
	lib/dnssec/dnssec.h \
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
	lib/dnssec/tsig.h \
	lib/dnssec/version.h

libdnssec_la_SOURCES = \
	lib/binary.c \
	lib/crypto.c \
	lib/error.c \
	lib/kasp/dir/escape.c \
	lib/kasp/dir/escape.h \
	lib/kasp/dir/file.c \
	lib/kasp/dir/file.h \
	lib/kasp/dir/json.c \
	lib/kasp/dir/json.h \
	lib/kasp/dir/policy.c \
	lib/kasp/dir/policy.h \
	lib/kasp/internal.h \
	lib/kasp/policy.c \
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
	lib/nsec/nsec.c \
	lib/p11/p11.c \
	lib/p11/p11.h \
	lib/random.c \
	lib/sign/der.c \
	lib/sign/der.h \
	lib/sign/sign.c \
	lib/tsig.c

# pkg-config
pkgconfig_DATA = libdnssec.pc
