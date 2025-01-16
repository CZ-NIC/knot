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
	contrib/licenses/ISC			\
	contrib/licenses/BSD-3-Clause		\
	contrib/licenses/GPL-2.0-or-later	\
	contrib/licenses/LGPL-2.0-or-later	\
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
	contrib/atomic.h			\
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
	contrib/redis/redismodule.h		\
	contrib/semaphore.c			\
	contrib/semaphore.h			\
	contrib/sockaddr.c			\
	contrib/sockaddr.h			\
	contrib/spinlock.h			\
	contrib/string.c			\
	contrib/string.h			\
	contrib/strtonum.h			\
	contrib/threads.c			\
	contrib/threads.h			\
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
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_acktr.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_acktr.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_addr.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_addr.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_balloc.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_balloc.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_bbr.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_bbr.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_buf.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_buf.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_cc.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_cc.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_cid.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_cid.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_conn.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_conn.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_conn_stat.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_conv.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_conv.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_crypto.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_crypto.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_err.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_err.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_frame_chain.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_frame_chain.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_gaptr.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_gaptr.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_idtr.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_idtr.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_ksl.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_ksl.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_log.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_log.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_macro.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_map.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_map.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_mem.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_mem.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_net.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_objalloc.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_objalloc.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_opl.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_opl.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_path.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_path.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_pkt.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_pkt.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_pktns_id.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_pmtud.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_pmtud.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_ppe.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_ppe.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_pq.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_pq.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_pv.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_pv.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_qlog.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_qlog.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_range.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_range.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_rcvry.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_ringbuf.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_ringbuf.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_rob.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_rob.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_rst.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_rst.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_rtb.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_rtb.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_settings.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_settings.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_str.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_str.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_strm.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_strm.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_transport_params.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_transport_params.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_tstamp.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_unreachable.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_unreachable.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_vec.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_vec.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_version.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_window_filter.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_window_filter.h \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_dcidtr.c \
	contrib/libngtcp2/ngtcp2/lib/ngtcp2_dcidtr.h \
	contrib/libngtcp2/ngtcp2/ngtcp2.h \
	contrib/libngtcp2/ngtcp2/ngtcp2_crypto.h \
	contrib/libngtcp2/ngtcp2/ngtcp2_crypto_gnutls.h \
	contrib/libngtcp2/ngtcp2/version.h
endif EMBEDDED_LIBNGTCP2
