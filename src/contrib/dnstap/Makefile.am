ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(top_srcdir)/src

EXTRA_DIST =                            \
	dnstap.proto

if HAVE_DNSTAP

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	$(AM_V_GEN)@PROTOC_C@ --c_out=. -I$(srcdir) $<

.proto.pb-c.h:
	$(AM_V_GEN)@PROTOC_C@ --c_out=. -I$(srcdir) $<

noinst_LTLIBRARIES = libdnstap.la

libdnstap_la_CPPFLAGS =			\
	$(AM_CPPFLAGS)			\
	$(CFLAG_VISIBILITY)

libdnstap_la_CFLAGS =			\
	$(DNSTAP_CFLAGS)

libdnstap_la_LDFLAGS =			\
	$(DNSTAP_LIBS)			\
	$(LDFLAG_EXCLUDE_LIBS)

libdnstap_la_SOURCES =			\
	convert.c			\
	convert.h			\
	dnstap.c			\
	dnstap.h			\
	message.c			\
	message.h			\
	reader.c			\
	reader.h			\
	writer.c			\
	writer.h

nodist_libdnstap_la_SOURCES =		\
	dnstap.pb-c.c			\
	dnstap.pb-c.h

BUILT_SOURCES = $(nodist_libdnstap_la_SOURCES)
CLEANFILES = $(nodist_libdnstap_la_SOURCES)

endif
