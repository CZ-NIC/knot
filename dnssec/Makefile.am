SUBDIRS = . tests

AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h

lib_LTLIBRARIES = libdnssec.la

libdnssec_la_CFLAGS = $(AM_CFLAGS) $(gnutls_CFLAGS) -Isrc -fvisibility=hidden
libdnssec_la_LDFLAGS = $(gnutls_LIBS) -version-info 0:1:0
libdnssec_la_SOURCES =	\
	src/binary.c \
	src/binary.h \
	src/error.h \
	src/hex.c \
	src/hex.h \
	src/key.c \
	src/key.h \
	src/keys/legacy.c \
	src/keys/legacy.h \
	src/keys/pubkey.c \
	src/keys/pubkey.h \
	src/keystore.c \
	src/keystore.h \
	src/keytag.c \
	src/keytag.h \
	src/shared.h \
	src/sign.c \
	src/sign.h \
	src/wire.h
