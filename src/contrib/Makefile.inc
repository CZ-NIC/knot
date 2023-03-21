noinst_LTLIBRARIES += libcontrib.la

libcontrib_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY)
libcontrib_la_LDFLAGS  = $(AM_LDFLAGS) $(LDFLAG_EXCLUDE_LIBS)
libcontrib_la_LIBADD   = $(pthread_LIBS)
libcontrib_LIBS        = libcontrib.la
if USE_GNUTLS_MEMSET
libcontrib_la_CPPFLAGS += $(gnutls_CFLAGS)
libcontrib_LIBS        += $(gnutls_LIBS)
endif USE_GNUTLS_MEMSET

EXTRA_DIST += \
	contrib/licenses/0BSD			\
	contrib/licenses/BSD-3-Clause		\
	contrib/licenses/LGPL-2.0		\
	contrib/licenses/MIT			\
	contrib/musl/LICENSE			\
	contrib/libngtcp2/LICENSE		\
	contrib/openbsd/LICENSE			\
	contrib/ucw/LICENSE			\
	contrib/url-parser/LICENSE		\
	contrib/url-parser/README.md		\
	contrib/dnstap/dnstap.proto

libcontrib_la_SOURCES = \
	contrib/asan.h				\
	contrib/base32hex.c			\
	contrib/base32hex.h			\
	contrib/base64.c			\
	contrib/base64.h			\
	contrib/base64url.c			\
	contrib/base64url.h			\
	contrib/conn_pool.c			\
	contrib/conn_pool.h			\
	contrib/color.h				\
	contrib/ctype.h				\
	contrib/files.c				\
	contrib/files.h				\
	contrib/getline.c			\
	contrib/getline.h			\
	contrib/json.c				\
	contrib/json.h				\
	contrib/macros.h			\
	contrib/mempattern.c			\
	contrib/mempattern.h			\
	contrib/musl/inet_ntop.c		\
	contrib/musl/inet_ntop.h		\
	contrib/net.c				\
	contrib/net.h				\
	contrib/os.h				\
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
	contrib/toeplitz.h			\
	contrib/tolower.h			\
	contrib/trim.h				\
	contrib/wire_ctx.h			\
	contrib/openbsd/siphash.c		\
	contrib/openbsd/siphash.h		\
	contrib/openbsd/strlcat.c		\
	contrib/openbsd/strlcat.h		\
	contrib/openbsd/strlcpy.c		\
	contrib/openbsd/strlcpy.h		\
	contrib/proxyv2/proxyv2.c		\
	contrib/proxyv2/proxyv2.h		\
	contrib/ucw/array-sort.h		\
	contrib/ucw/binsearch.h			\
	contrib/ucw/heap.c			\
	contrib/ucw/heap.h			\
	contrib/ucw/lists.c			\
	contrib/ucw/lists.h			\
	contrib/ucw/mempool.c			\
	contrib/ucw/mempool.h			\
	contrib/url-parser/url_parser.c		\
	contrib/url-parser/url_parser.h		\
	contrib/vpool/vpool.c			\
	contrib/vpool/vpool.h

if HAVE_LIBDNSTAP
noinst_LTLIBRARIES += libdnstap.la

libdnstap_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(DNSTAP_CFLAGS)
libdnstap_la_LDFLAGS  = $(AM_LDFLAGS) $(LDFLAG_EXCLUDE_LIBS)
libdnstap_LIBS        = libdnstap.la $(DNSTAP_LIBS)

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

if EMBEDDED_LIBNGTCP2
noinst_LTLIBRARIES += libembngtcp2.la

libembngtcp2_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) \
                           $(embedded_libngtcp2_CFLAGS) $(gnutls_CFLAGS)
libembngtcp2_la_LDFLAGS  = $(AM_LDFLAGS) $(LDFLAG_EXCLUDE_LIBS)
libembngtcp2_LIBS        = libembngtcp2.la $(embedded_libngtcp2_LIBS) $(gnutls_LIBS)

libembngtcp2_la_SOURCES = \
	contrib/libngtcp2/ngtcp2/crypto/gnutls.c \
	contrib/libngtcp2/ngtcp2/crypto/shared.c \
	contrib/libngtcp2/ngtcp2/crypto/shared.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_macro.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_net.h \
	contrib/libngtcp2/ngtcp2/ngtcp2_crypto.h \
	contrib/libngtcp2/ngtcp2/ngtcp2_crypto_gnutls.h
endif EMBEDDED_LIBNGTCP2
