noinst_LTLIBRARIES += libcontrib.la

libcontrib_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY)
libcontrib_la_LDFLAGS  = $(AM_LDFLAGS) $(LDFLAG_EXCLUDE_LIBS)
libcontrib_la_LIBADD   = $(pthread_LIBS) -lssl -lcrypto

if !HAVE_LMDB
libcontrib_la_CPPFLAGS += -include contrib/lmdb/mute_warnings.h
endif !HAVE_LMDB
if USE_GNUTLS_MEMSET
libcontrib_la_CPPFLAGS += $(gnutls_CFLAGS)
libcontrib_la_LIBADD   += $(gnutls_LIBS)
endif USE_GNUTLS_MEMSET

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
	contrib/semaphore.c			\
	contrib/semaphore.h			\
	contrib/sockaddr.c			\
	contrib/sockaddr.h			\
	contrib/spinlock.h			\
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
	contrib/ucw/mempool.h			\
	contrib/vpool/vpool.c			\
	contrib/vpool/vpool.h			\
	contrib/quicly/picotls/picotls/asn1.h			\
	contrib/quicly/picotls/picotls/certificate_compression.h			\
	contrib/quicly/picotls/picotls/fxx.h			\
	contrib/quicly/picotls/picotls/minicrypto.h			\
	contrib/quicly/picotls/picotls/openssl.h			\
	contrib/quicly/picotls/picotls/pembase64.h			\
	contrib/quicly/picotls/picotls/ptlsbcrypt.h			\
	contrib/quicly/quicly/cc.h			\
	contrib/quicly/constants.h			\
	contrib/quicly/defaults.h			\
	contrib/quicly/frame.h			\
	contrib/quicly/linklist.h			\
	contrib/quicly/loss.h			\
	contrib/quicly/maxsender.h			\
	contrib/quicly/ranges.h			\
	contrib/quicly/recvstate.h			\
	contrib/quicly/sendstate.h			\
	contrib/quicly/sentmap.h			\
	contrib/quicly/streambuf.h			\
	contrib/quicly/picotls/picotls.h			\
	contrib/quicly/quicly.h			\
	contrib/quicly/klib/bgzf.h			\
	contrib/quicly/klib/kbit.h			\
	contrib/quicly/klib/kbtree.h			\
	contrib/quicly/klib/kdq.h			\
	contrib/quicly/klib/kexpr.h			\
	contrib/quicly/klib/kgraph.h			\
	contrib/quicly/klib/khash.h			\
	contrib/quicly/klib/khmm.h			\
	contrib/quicly/klib/klist.h			\
	contrib/quicly/klib/kmath.h			\
	contrib/quicly/klib/knetfile.h			\
	contrib/quicly/klib/knhx.h			\
	contrib/quicly/klib/kseq.h			\
	contrib/quicly/klib/kson.h			\
	contrib/quicly/klib/ksort.h			\
	contrib/quicly/klib/kstring.h			\
	contrib/quicly/klib/ksw.h			\
	contrib/quicly/klib/kthread.h			\
	contrib/quicly/klib/kurl.h			\
	contrib/quicly/klib/kvec.h			\
	contrib/quicly/picotls/openssl.c			\
	contrib/quicly/picotls/pembase64.c			\
	contrib/quicly/picotls/picotls.c			\
	contrib/quicly/cc-reno.c			\
	contrib/quicly/defaults.c			\
	contrib/quicly/frame.c			\
	contrib/quicly/quicly.c			\
	contrib/quicly/ranges.c			\
	contrib/quicly/recvstate.c			\
	contrib/quicly/sendstate.c			\
	contrib/quicly/sentmap.c			\
	contrib/quicly/streambuf.c

if !HAVE_LMDB
libcontrib_la_SOURCES += \
	contrib/lmdb/lmdb.h			\
	contrib/lmdb/mdb.c			\
	contrib/lmdb/midl.c			\
	contrib/lmdb/midl.h			\
	contrib/lmdb/mute_warnings.h
endif !HAVE_LMDB

if HAVE_LIBDNSTAP
noinst_LTLIBRARIES += libdnstap.la

libdnstap_la_CPPFLAGS = $(AM_CPPFLAGS) $(DNSTAP_CFLAGS)
libdnstap_la_LIBADD   = $(DNSTAP_LIBS)

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	$(AM_V_GEN)@PROTOC_C@ --c_out=. -I$(srcdir) $<

.proto.pb-c.h:
	$(AM_V_GEN)@PROTOC_C@ --c_out=. -I$(srcdir) $<

libdnstap_la_SOURCES = \
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

nodist_libdnstap_la_SOURCES = \
	contrib/dnstap/dnstap.pb-c.c	\
	contrib/dnstap/dnstap.pb-c.h

BUILT_SOURCES += $(nodist_libdnstap_la_SOURCES)
CLEANFILES    += $(nodist_libdnstap_la_SOURCES)
endif HAVE_LIBDNSTAP
