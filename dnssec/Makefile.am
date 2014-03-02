SUBDIRS = tests

# Knot DNS common sources depedency (temporary)
#AM_CPPFLAGS = -I$(top_srcdir)/src

lib_LTLIBRARIES = libdnssec.la

libdnssec_la_CFLAGS = $(AM_CFLAGS) $(gnutls_CFLAGS) -fvisibility=hidden
libdnssec_la_LDFLAGS = $(gnutls_LIBS) -version-info 0:1:0
libdnssec_la_SOURCES =	\
	src/binary.c \
	src/binary.h \
	src/error.h \
	src/key.c \
	src/key.h \
	src/keys/legacy.c \
	src/keys/legacy.h \
	src/keystore.c \
	src/keystore.h \
	src/keytag.c \
	src/keytag.h \
	src/pkcs8.c \
	src/shared.h \
	src/sign.c \
	src/sign.h \
	src/wire.h
