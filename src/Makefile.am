ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
SUBDIRS = zscanner dnssec dnstap .

lib_LTLIBRARIES = libknot-int.la libknot.la
noinst_LTLIBRARIES =

if HAVE_DAEMON
sbin_PROGRAMS = knotc knotd
noinst_LTLIBRARIES += libknotd.la
endif

if HAVE_UTILS
bin_PROGRAMS = kdig khost knsupdate
noinst_LTLIBRARIES += libknotus.la
endif

# $(YACC) will generate header file
AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h	\
	-DCONFIG_DIR='"${config_dir}"'		\
	-DSTORAGE_DIR='"${storage_dir}"'	\
	-DRUN_DIR='"${run_dir}"'		\
	-I$(srcdir)/dnssec/lib

AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = $(CODE_COVERAGE_LDFLAGS)
AM_YFLAGS = -d
libknotd_la_YFLAGS = -pcf_ -d
libknotd_la_LFLAGS = # TODO: reentrant parser, prefix

if HAVE_DAEMON

BUILT_SOURCES =					\
	knot/conf/libknotd_la-cf-lex.c		\
	knot/conf/libknotd_la-cf-parse.c	\
	knot/conf/libknotd_la-cf-parse.h

CLEANFILES =					\
	knot/conf/libknotd_la-cf-lex.c		\
	knot/conf/libknotd_la-cf-parse.c	\
	knot/conf/libknotd_la-cf-parse.h

knotc_SOURCES =					\
	knot/ctl/knotc_main.c

knotd_SOURCES =					\
	knot/main.c

endif # HAVE_DAEMON

if HAVE_UTILS

kdig_SOURCES =					\
	utils/kdig/kdig_exec.c			\
	utils/kdig/kdig_exec.h			\
	utils/kdig/kdig_main.c			\
	utils/kdig/kdig_params.c		\
	utils/kdig/kdig_params.h

khost_SOURCES =					\
	utils/kdig/kdig_exec.c			\
	utils/kdig/kdig_exec.h			\
	utils/kdig/kdig_params.c		\
	utils/kdig/kdig_params.h		\
	utils/khost/khost_main.c		\
	utils/khost/khost_params.c		\
	utils/khost/khost_params.h

knsupdate_SOURCES =				\
	utils/knsupdate/knsupdate_exec.c	\
	utils/knsupdate/knsupdate_exec.h	\
	utils/knsupdate/knsupdate_main.c	\
	utils/knsupdate/knsupdate_params.c	\
	utils/knsupdate/knsupdate_params.h

# static: utilities shared
libknotus_la_SOURCES =				\
	utils/common/exec.c			\
	utils/common/exec.h			\
	utils/common/hex.c			\
	utils/common/hex.h			\
	utils/common/msg.c			\
	utils/common/msg.h			\
	utils/common/netio.c			\
	utils/common/netio.h			\
	utils/common/params.c			\
	utils/common/params.h			\
	utils/common/resolv.c			\
	utils/common/resolv.h			\
	utils/common/strtonum.h			\
	utils/common/token.c			\
	utils/common/token.h

endif # HAVE_UTILS

# dynamic: libknot internal headers
nobase_libknot_int_la_HEADERS =			\
	libknot/internal/array-sort.h		\
	libknot/internal/base32hex.h		\
	libknot/internal/base64.h		\
	libknot/internal/binsearch.h		\
	libknot/internal/endian.h		\
	libknot/internal/errors.h		\
	libknot/internal/getline.h		\
	libknot/internal/heap.h			\
	libknot/internal/hhash.h		\
	libknot/internal/lists.h		\
	libknot/internal/macros.h		\
	libknot/internal/mem.h			\
	libknot/internal/mempattern.h		\
	libknot/internal/mempool.h		\
	libknot/internal/namedb/namedb.h	\
	libknot/internal/namedb/namedb_lmdb.h	\
	libknot/internal/namedb/namedb_trie.h	\
	libknot/internal/net.h			\
	libknot/internal/print.h		\
	libknot/internal/sockaddr.h		\
	libknot/internal/strlcat.h		\
	libknot/internal/strlcpy.h		\
	libknot/internal/tolower.h		\
	libknot/internal/trie/hat-trie.h	\
	libknot/internal/trie/murmurhash3.h	\
	libknot/internal/utils.h		\
	libknot/internal/yparser/yparser.h	\
	libknot/internal/yparser/ypformat.h	\
	libknot/internal/yparser/ypscheme.h	\
	libknot/internal/yparser/yptrafo.h

# dynamic: libknot internal sources
libknot_int_la_SOURCES =			\
	libknot/internal/base32hex.c		\
	libknot/internal/base64.c		\
	libknot/internal/errors.c		\
	libknot/internal/getline.c		\
	libknot/internal/heap.c			\
	libknot/internal/hhash.c		\
	libknot/internal/lists.c		\
	libknot/internal/mem.c			\
	libknot/internal/mempattern.c		\
	libknot/internal/mempool.c		\
	libknot/internal/namedb/namedb_lmdb.c	\
	libknot/internal/namedb/namedb_trie.c	\
	libknot/internal/net.c			\
	libknot/internal/print.c		\
	libknot/internal/sockaddr.c		\
	libknot/internal/strlcat.c		\
	libknot/internal/strlcpy.c		\
	libknot/internal/tolower.c		\
	libknot/internal/trie/hat-trie.c	\
	libknot/internal/trie/murmurhash3.c	\
	libknot/internal/utils.c		\
	libknot/internal/yparser/yparser.c	\
	libknot/internal/yparser/ypbody.c	\
	libknot/internal/yparser/ypformat.c	\
	libknot/internal/yparser/ypscheme.c	\
	libknot/internal/yparser/yptrafo.c	\
	$(libknot_int_la_HEADERS)

# dynamic: libknot headers
nobase_libknot_la_HEADERS =			\
	libknot/binary.h			\
	libknot/consts.h			\
	libknot/descriptor.h			\
	libknot/dname.h				\
	libknot/dnssec/key.h			\
	libknot/errcode.c			\
	libknot/errcode.h			\
	libknot/libknot.h			\
	libknot/packet/compr.h			\
	libknot/packet/pkt.h			\
	libknot/packet/rrset-wire.h		\
	libknot/packet/wire.h			\
	libknot/processing/layer.h		\
	libknot/processing/overlay.h		\
	libknot/processing/requestor.h		\
	libknot/rdata.h				\
	libknot/rdataset.h			\
	libknot/rrset-dump.h			\
	libknot/rrset.h				\
	libknot/rrtype/aaaa.h			\
	libknot/rrtype/dnskey.h			\
	libknot/rrtype/naptr.h			\
	libknot/rrtype/nsec.h			\
	libknot/rrtype/nsec3.h			\
	libknot/rrtype/nsec3param.h		\
	libknot/rrtype/opt.h			\
	libknot/rrtype/rdname.h			\
	libknot/rrtype/rrsig.h			\
	libknot/rrtype/soa.h			\
	libknot/rrtype/tsig.h			\
	libknot/tsig-op.h

# dynamic: libknot sources
libknot_la_SOURCES =				\
	libknot/binary.c			\
	libknot/consts.c			\
	libknot/descriptor.c			\
	libknot/dname.c				\
	libknot/dnssec/key.c			\
	libknot/errcode.c			\
	libknot/packet/compr.c			\
	libknot/packet/pkt.c			\
	libknot/packet/rrset-wire.c		\
	libknot/processing/layer.c		\
	libknot/processing/overlay.c		\
	libknot/processing/requestor.c		\
	libknot/rdata.c				\
	libknot/rdataset.c			\
	libknot/rrset-dump.c			\
	libknot/rrset.c				\
	libknot/rrtype/nsec3.c			\
	libknot/rrtype/nsec3param.c		\
	libknot/rrtype/opt.c			\
	libknot/rrtype/tsig.c			\
	libknot/tsig-op.c			\
	$(libknot_la_HEADERS)

if HAVE_DAEMON

# static: server shared
libknotd_la_SOURCES =				\
	knot/conf/cf-lex.l			\
	knot/conf/cf-parse.y			\
	knot/conf/conf.c			\
	knot/conf/conf.h			\
	knot/conf/extra.c			\
	knot/conf/extra.h			\
	knot/conf/includes.c			\
	knot/conf/includes.h			\
	knot/ctl/estimator.c			\
	knot/ctl/estimator.h			\
	knot/ctl/process.c			\
	knot/ctl/process.h			\
	knot/ctl/remote.c			\
	knot/ctl/remote.h			\
	knot/dnssec/context.c			\
	knot/dnssec/context.h			\
	knot/dnssec/nsec-chain.c		\
	knot/dnssec/nsec-chain.h		\
	knot/dnssec/nsec3-chain.c		\
	knot/dnssec/nsec3-chain.h		\
	knot/dnssec/policy.c			\
	knot/dnssec/policy.h			\
	knot/dnssec/rrset-sign.c		\
	knot/dnssec/rrset-sign.h		\
	knot/dnssec/zone-events.c		\
	knot/dnssec/zone-events.h		\
	knot/dnssec/zone-keys.c			\
	knot/dnssec/zone-keys.h			\
	knot/dnssec/zone-nsec.c			\
	knot/dnssec/zone-nsec.h			\
	knot/dnssec/zone-sign.c			\
	knot/dnssec/zone-sign.h			\
	knot/modules/synth_record.c		\
	knot/modules/synth_record.h		\
	knot/modules/dnsproxy.c			\
	knot/modules/dnsproxy.h			\
	knot/nameserver/axfr.c			\
	knot/nameserver/axfr.h			\
	knot/nameserver/capture.c		\
	knot/nameserver/capture.h		\
	knot/nameserver/chaos.c			\
	knot/nameserver/chaos.h			\
	knot/nameserver/internet.c		\
	knot/nameserver/internet.h		\
	knot/nameserver/ixfr.c			\
	knot/nameserver/ixfr.h			\
	knot/nameserver/notify.c		\
	knot/nameserver/notify.h		\
	knot/nameserver/nsec_proofs.c		\
	knot/nameserver/nsec_proofs.h		\
	knot/nameserver/process_answer.c	\
	knot/nameserver/process_answer.h	\
	knot/nameserver/process_query.c		\
	knot/nameserver/process_query.h		\
	knot/nameserver/query_module.c		\
	knot/nameserver/query_module.h		\
	knot/nameserver/tsig_ctx.c		\
	knot/nameserver/tsig_ctx.h		\
	knot/nameserver/update.c		\
	knot/nameserver/update.h		\
	knot/common/debug.h			\
	knot/common/evsched.c			\
	knot/common/evsched.h			\
	knot/common/fdset.c			\
	knot/common/fdset.h			\
	knot/common/log.c			\
	knot/common/log.h			\
	knot/common/ref.c			\
	knot/common/ref.h			\
	knot/common/time.h			\
	knot/common/trim.h			\
	knot/server/dthreads.c			\
	knot/server/dthreads.h			\
	knot/server/journal.c			\
	knot/server/journal.h			\
	knot/server/rrl.c			\
	knot/server/rrl.h			\
	knot/server/serialization.c		\
	knot/server/serialization.h		\
	knot/server/server.c			\
	knot/server/server.h			\
	knot/server/tcp-handler.c		\
	knot/server/tcp-handler.h		\
	knot/server/udp-handler.c		\
	knot/server/udp-handler.h		\
	knot/updates/acl.c			\
	knot/updates/acl.h			\
	knot/updates/apply.c			\
	knot/updates/apply.h			\
	knot/updates/changesets.c		\
	knot/updates/changesets.h		\
	knot/updates/ddns.c			\
	knot/updates/ddns.h			\
	knot/updates/zone-update.c		\
	knot/updates/zone-update.h		\
	knot/worker/pool.c			\
	knot/worker/pool.h			\
	knot/worker/queue.c			\
	knot/worker/queue.h			\
	knot/zone/contents.c			\
	knot/zone/contents.h			\
	knot/zone/events/events.c		\
	knot/zone/events/events.h		\
	knot/zone/events/handlers.c		\
	knot/zone/events/handlers.h		\
	knot/zone/events/replan.c		\
	knot/zone/events/replan.h		\
	knot/zone/node.c			\
	knot/zone/node.h			\
	knot/zone/semantic-check.c		\
	knot/zone/semantic-check.h		\
	knot/zone/serial.c			\
	knot/zone/serial.h			\
	knot/zone/timers.c			\
	knot/zone/timers.h			\
	knot/zone/zone-diff.c			\
	knot/zone/zone-diff.h			\
	knot/zone/zone-dump.c			\
	knot/zone/zone-dump.h			\
	knot/zone/zone-load.c			\
	knot/zone/zone-load.h			\
	knot/zone/zone-tree.c			\
	knot/zone/zone-tree.h			\
	knot/zone/zone.c			\
	knot/zone/zone.h			\
	knot/zone/zonedb-load.c			\
	knot/zone/zonedb-load.h			\
	knot/zone/zonedb.c			\
	knot/zone/zonedb.h			\
	knot/zone/zonefile.c			\
	knot/zone/zonefile.h

endif # HAVE_DAEMON

# linking
libknot_int_la_CPPFLAGS = $(AM_CPPFLAGS) $(lmdb_CFLAGS)
libknot_int_la_CFLAGS = $(AM_CFLAGS) -fvisibility=default
libknot_int_la_LDFLAGS = $(AM_LDFLAGS) $(RELEASE_INFO) $(VERSION_INFO) $(lmdb_LIBS)

libknot_la_CPPFLAGS = $(AM_CPPFLAGS)
libknot_la_LDFLAGS = $(AM_LDFLAGS) $(RELEASE_INFO) $(VERSION_INFO)
libknot_la_LIBADD  = libknot-int.la dnssec/libdnssec.la zscanner/libzscanner.la

if HAVE_DAEMON

libknotd_la_CPPFLAGS  = $(AM_CPPFLAGS) $(systemd_CFLAGS)
libknotd_la_LDFLAGS = $(AM_LDFLAGS) $(systemd_LIBS)
libknotd_la_LIBADD = libknot.la

libknotus_la_CPPFLAGS = $(AM_CPPFLAGS) $(libidn_CFLAGS)
libknotus_la_LDFLAGS = $(AM_LDFLAGS) $(libidn_LIBS)
libknotus_la_LIBADD = libknot.la

endif # HAVE_DAEMON

# includes
libknot_ladir = $(includedir)
libknot_int_ladir = $(includedir)

if HAVE_DAEMON

# sbin programs
knotd_LDADD = libknot.la libknotd.la
knotc_LDADD = libknot.la libknotd.la

endif # HAVE_DAEMON

if HAVE_UTILS

# bin programs
BIN_LIBS = dnssec/libdnssec.la libknot.la libknot-int.la libknotus.la
kdig_LDADD       = $(BIN_LIBS) $(libidn_LIBS)
khost_LDADD      = $(BIN_LIBS) $(libidn_LIBS)
knsupdate_LDADD  = $(BIN_LIBS) zscanner/libzscanner.la

endif # HAVE_UTILS


if HAVE_DNSTAP

if HAVE_DAEMON
libknotd_la_SOURCES +=				\
	knot/modules/dnstap.c			\
	knot/modules/dnstap.h
libknotd_la_LIBADD += dnstap/libdnstap.la
endif # HAVE_DAEMOM

if HAVE_UTILS
kdig_LDADD         += dnstap/libdnstap.la
khost_LDADD        += dnstap/libdnstap.la
endif # HAVE_UTILS

endif # HAVE_DNSTAP

if HAVE_DAEMON
# rose sources and client tool
if HAVE_ROSEDB
libknotd_la_SOURCES +=				\
	knot/modules/rosedb.c			\
	knot/modules/rosedb.h

rosedb_tool_SOURCES =				\
	knot/modules/rosedb_tool.c

if HAVE_UTILS
bin_PROGRAMS += rosedb_tool
rosedb_tool_LDADD = libknot.la libknotd.la
endif # HAVE_UTILS
endif # HAVE_ROSEDB
endif # HAVE_DAEMON

if !HAVE_LMDB
libknot_int_la_SOURCES +=		\
	libknot/internal/namedb/mdb.c	\
	libknot/internal/namedb/midl.c
nobase_libknot_int_la_HEADERS +=	\
	libknot/internal/namedb/lmdb.h	\
	libknot/internal/namedb/midl.h
libknot_int_la_CPPFLAGS +=		\
	-I$(srcdir)/libknot/internal/namedb/
endif

# pkg-config
pkgconfig_DATA = libknot.pc libknot-int.pc

if HAVE_DAEMON
# Create storage and run-time directories
install-data-hook:
	$(INSTALL) -d $(DESTDIR)/@config_dir@
	$(INSTALL) -d $(DESTDIR)/@run_dir@
	$(INSTALL) -d $(DESTDIR)/@storage_dir@
endif # HAVE_DAEMON
