if HAVE_UTILS

noinst_LTLIBRARIES = libutils.la

AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(srcdir)/../shared \
	-I$(srcdir)/../lib/dnssec \
	-I$(srcdir)/../lib \
	-I$(top_srcdir)/src \
	$(gnutls_CFLAGS)

libutils_la_LIBADD = \
	$(builddir)/../libdnssec.la \
	$(builddir)/../libshared.la \
	$(top_builddir)/src/zscanner/libzscanner.la

libutils_la_SOURCES = \
	cmdparse/command.c \
	cmdparse/command.h \
	cmdparse/match.h \
	cmdparse/parameter.c \
	cmdparse/parameter.h \
	cmdparse/value.c \
	cmdparse/value.h \
	legacy/key.c \
	legacy/key.h \
	legacy/privkey.c \
	legacy/privkey.h \
	legacy/pubkey.c \
	legacy/pubkey.h \
	print.h

keymgr_LDADD = \
	libutils.la

knsec3hash_LDADD = \
	$(builddir)/../libdnssec.la \
	$(builddir)/../libshared.la

sbin_PROGRAMS = \
	keymgr

bin_PROGRAMS =	\
	knsec3hash

endif # HAVE_UTILS
