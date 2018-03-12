noinst_LTLIBRARIES += libcontrib.la

libcontrib_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY)
libcontrib_la_LDFLAGS  = $(AM_LDFLAGS) $(LDFLAG_EXCLUDE_LIBS)

EXTRA_DIST += \
	contrib/licenses/0BSD			\
	contrib/licenses/BSD-3-Clause		\
	contrib/licenses/LGPL-2.0		\
	contrib/licenses/OLDAP-2.8		\
	contrib/lmdb/LICENSE			\
	contrib/openbsd/LICENSE			\
	contrib/ucw/LICENSE			\
	contrib/dnstap/dnstap.proto

libcontrib_la_SOURCES = \
	contrib/asan.h				\
	contrib/base32hex.c			\
	contrib/base32hex.h			\
	contrib/base64.c			\
	contrib/base64.h			\
	contrib/ctype.h				\
	contrib/dynarray.h			\
	contrib/files.c				\
	contrib/files.h				\
	contrib/getline.c			\
	contrib/getline.h			\
	contrib/macros.h			\
	contrib/mempattern.c			\
	contrib/mempattern.h			\
	contrib/net.c				\
	contrib/net.h				\
	contrib/qp-trie/trie.c			\
	contrib/qp-trie/trie.h			\
	contrib/sockaddr.c			\
	contrib/sockaddr.h			\
	contrib/string.c			\
	contrib/string.h			\
	contrib/strtonum.h			\
	contrib/time.c				\
	contrib/time.h				\
	contrib/tolower.h			\
	contrib/trim.h				\
	contrib/wire_ctx.h			\
	contrib/openbsd/siphash.c		\
	contrib/openbsd/siphash.h		\
	contrib/openbsd/strlcat.c		\
	contrib/openbsd/strlcat.h		\
	contrib/openbsd/strlcpy.c		\
	contrib/openbsd/strlcpy.h		\
	contrib/ucw/array-sort.h		\
	contrib/ucw/binsearch.h			\
	contrib/ucw/heap.c			\
	contrib/ucw/heap.h			\
	contrib/ucw/lists.c			\
	contrib/ucw/lists.h			\
	contrib/ucw/mempool.c			\
	contrib/ucw/mempool.h

if !HAVE_LMDB
libcontrib_la_SOURCES += \
	contrib/lmdb/lmdb.h			\
	contrib/lmdb/mdb.c			\
	contrib/lmdb/midl.c			\
	contrib/lmdb/midl.h
endif !HAVE_LMDB

if HAVE_DNSTAP
SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	$(AM_V_GEN)@PROTOC_C@ --c_out=. -I$(srcdir) $<

.proto.pb-c.h:
	$(AM_V_GEN)@PROTOC_C@ --c_out=. -I$(srcdir) $<

libcontrib_la_SOURCES += \
	contrib/dnstap/convert.c	\
	contrib/dnstap/convert.h	\
	contrib/dnstap/dnstap.c		\
	contrib/dnstap/dnstap.h		\
	contrib/dnstap/message.c	\
	contrib/dnstap/message.h	\
	contrib/dnstap/reader.c		\
	contrib/dnstap/reader.h		\
	contrib/dnstap/writer.c		\
	contrib/dnstap/writer.h

nodist_libcontrib_la_SOURCES = \
	contrib/dnstap/dnstap.pb-c.c	\
	contrib/dnstap/dnstap.pb-c.h

libcontrib_la_CPPFLAGS += $(DNSTAP_CFLAGS)
libcontrib_la_LDFLAGS  += $(DNSTAP_LIBS)

BUILT_SOURCES += $(nodist_libcontrib_la_SOURCES)
CLEANFILES    += $(nodist_libcontrib_la_SOURCES)
endif HAVE_DNSTAP
