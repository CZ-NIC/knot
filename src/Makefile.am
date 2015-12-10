ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
SUBDIRS = zscanner dnssec contrib/dnstap .

lib_LTLIBRARIES =				\
	libknot.la
noinst_LTLIBRARIES = 				\
	libcontrib.la				\
	libknot-internal.la			\
	libknot-yparser.la

AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h	\
	-DCONFIG_DIR='"${config_dir}"'		\
	-DSTORAGE_DIR='"${storage_dir}"'	\
	-DRUN_DIR='"${run_dir}"'		\
	-I$(srcdir)/dnssec/lib

AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = $(CODE_COVERAGE_LDFLAGS)

######################
# Knot DNS Libraries #
######################

libcontrib_ladir = $(includedir)
nobase_libcontrib_la_HEADERS =			\
	contrib/base32hex.h			\
	contrib/base64.h			\
	contrib/endian.h			\
	contrib/getline.h			\
	contrib/lookup.h			\
	contrib/macros.h			\
	contrib/net.h				\
	contrib/print.h				\
	contrib/sockaddr.h			\
	contrib/string.h			\
	contrib/tolower.h			\
	contrib/wire.h				\
	contrib/wire_ctx.h			\
	contrib/openbsd/strlcat.h		\
	contrib/openbsd/strlcpy.h		\
	contrib/ucw/array-sort.h		\
	contrib/ucw/binsearch.h			\
	contrib/ucw/heap.h			\
	contrib/ucw/mempool.h

# dynamic: libknot headers
libknot_ladir = $(includedir)
nobase_libknot_la_HEADERS =			\
	libknot/attribute.h			\
	libknot/binary.h			\
	libknot/codes.h				\
	libknot/consts.h			\
	libknot/descriptor.h			\
	libknot/dname.h				\
	libknot/dnssec/rrset-sign.h		\
	libknot/errcode.h			\
	libknot/error.h				\
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
	libknot/rrtype/txt.h			\
	libknot/tsig-op.h			\
	libknot/tsig.h

libknot_internal_ladir = $(includedir)
nobase_libknot_internal_la_HEADERS = 		\
	libknot/internal/hhash.h		\
	libknot/internal/lists.h		\
	libknot/internal/mempattern.h		\
	libknot/internal/namedb/namedb.h	\
	libknot/internal/namedb/namedb_lmdb.h	\
	libknot/internal/namedb/namedb_trie.h	\
	libknot/internal/trie/hat-trie.h	\
	libknot/internal/trie/murmurhash3.h

libknot_yparser_ladir = $(includedir)
nobase_libknot_yparser_la_HEADERS = 		\
	libknot/yparser/yparser.h		\
	libknot/yparser/ypformat.h		\
	libknot/yparser/ypscheme.h		\
	libknot/yparser/yptrafo.h

# dynamic: libknot sources
libcontrib_la_SOURCES = 			\
	contrib/base32hex.c			\
	contrib/base64.c			\
	contrib/getline.c			\
	contrib/net.c				\
	contrib/print.c				\
	contrib/sockaddr.c			\
	contrib/string.c			\
	contrib/openbsd/strlcat.c		\
	contrib/openbsd/strlcpy.c		\
	contrib/ucw/heap.c			\
	contrib/ucw/mempool.c			\
	$(nobase_libcontrib_la_HEADERS)

libknot_la_SOURCES =				\
	libknot/binary.c			\
	libknot/codes.c				\
	libknot/descriptor.c			\
	libknot/dname.c				\
	libknot/dnssec/rrset-sign.c		\
	libknot/error.c				\
	libknot/packet/compr.c			\
	libknot/packet/pkt.c			\
	libknot/packet/rrset-wire.c		\
	libknot/packet/wire.c			\
	libknot/processing/layer.c		\
	libknot/processing/overlay.c		\
	libknot/processing/requestor.c		\
	libknot/rdata.c				\
	libknot/rdataset.c			\
	libknot/rrset-dump.c			\
	libknot/rrset.c				\
	libknot/rrtype/dnskey.c			\
	libknot/rrtype/naptr.c			\
	libknot/rrtype/nsec3.c			\
	libknot/rrtype/nsec3param.c		\
	libknot/rrtype/opt.c			\
	libknot/rrtype/rrsig.c			\
	libknot/rrtype/soa.c			\
	libknot/rrtype/tsig.c			\
	libknot/tsig-op.c			\
	libknot/tsig.c				\
	$(nobase_libknot_la_HEADERS)

libknot_yparser_la_SOURCES = 			\
	libknot/yparser/yparser.c		\
	libknot/yparser/ypbody.c		\
	libknot/yparser/ypformat.c		\
	libknot/yparser/ypscheme.c		\
	libknot/yparser/yptrafo.c		\
	$(nobase_libknot_yparser_la_HEADERS)

libknot_internal_la_SOURCES = 			\
	libknot/internal/hhash.c		\
	libknot/internal/lists.c		\
	libknot/internal/mempattern.c		\
	libknot/internal/namedb/namedb_lmdb.c	\
	libknot/internal/namedb/namedb_trie.c	\
	libknot/internal/trie/hat-trie.c	\
	libknot/internal/trie/murmurhash3.c	\
	$(nobase_libknot_internal_la_HEADERS)

libcontrib_la_CPPFLAGS = $(AM_CPPFLAGS)
libcontrib_la_CFLAGS = $(AM_CFLAGS)

libknot_internal_la_CPPFLAGS = $(AM_CPPFLAGS) $(lmdb_CFLAGS)
libknot_internal_la_CFLAGS = $(AM_CFLAGS)

libknot_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(lmdb_CFLAGS)
libknot_la_CFLAGS = $(AM_CFLAGS)
libknot_la_LDFLAGS = $(AM_LDFLAGS) $(libknot_VERSION_INFO) $(lmdb_LIBS)
libknot_la_LIBADD = dnssec/libdnssec.la libcontrib.la libknot-internal.la

# pkg-config
pkgconfig_DATA = libknot.pc

if !HAVE_LMDB
libknot_internal_la_SOURCES +=			\
	contrib/lmdb/lmdb.h			\
	contrib/lmdb/mdb.c			\
	contrib/lmdb/midl.c			\
	contrib/lmdb/midl.h
libknot_internal_la_CPPFLAGS +=			\
	-I$(srcdir)/contrib/lmdb/
endif

###################
# Knot DNS Daemon #
###################

if HAVE_DAEMON

sbin_PROGRAMS = knotc knotd
libexec_PROGRAMS = knot1to2
noinst_LTLIBRARIES += libknotd.la

EXTRA_DIST = 					\
	utils/knot1to2/cf-lex.l			\
	utils/knot1to2/cf-parse.y

knotc_SOURCES =					\
	knot/ctl/knotc_main.c

knotd_SOURCES =					\
	knot/main.c

knot1to2_SOURCES =				\
	utils/knot1to2/cf-lex.c			\
	utils/knot1to2/cf-parse.tab.c		\
	utils/knot1to2/cf-parse.tab.h		\
	utils/knot1to2/extra.c			\
	utils/knot1to2/extra.h			\
	utils/knot1to2/includes.c		\
	utils/knot1to2/includes.h		\
	utils/knot1to2/main.c			\
	utils/knot1to2/scheme.h

# static: server shared
libknotd_la_SOURCES =				\
	knot/conf/base.c			\
	knot/conf/base.h			\
	knot/conf/conf.c			\
	knot/conf/conf.h			\
	knot/conf/confdb.c			\
	knot/conf/confdb.h			\
	knot/conf/confio.c			\
	knot/conf/confio.h			\
	knot/conf/scheme.c			\
	knot/conf/scheme.h			\
	knot/conf/tools.c			\
	knot/conf/tools.h			\
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
	knot/dnssec/zone-events.c		\
	knot/dnssec/zone-events.h		\
	knot/dnssec/zone-keys.c			\
	knot/dnssec/zone-keys.h			\
	knot/dnssec/zone-nsec.c			\
	knot/dnssec/zone-nsec.h			\
	knot/dnssec/zone-sign.c			\
	knot/dnssec/zone-sign.h			\
	knot/modules/dnsproxy.c			\
	knot/modules/dnsproxy.h			\
	knot/modules/online_sign/module.c	\
	knot/modules/online_sign/module.h	\
	knot/modules/online_sign/nsec_next.c	\
	knot/modules/online_sign/nsec_next.h	\
	knot/modules/synth_record.c		\
	knot/modules/synth_record.h		\
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

libknotd_la_CPPFLAGS  = $(AM_CPPFLAGS) $(systemd_CFLAGS) $(liburcu_CFLAGS)
libknotd_la_LDFLAGS = $(AM_LDFLAGS) $(systemd_LIBS) $(liburcu_LIBS)
libknotd_la_LIBADD = libknot.la libknot-yparser.la zscanner/libzscanner.la $(liburcu_LIBS)

knotd_CPPFLAGS = $(AM_CPPFLAGS) $(liburcu_CFLAGS)
knotd_LDADD = libknotd.la $(liburcu_LIBS)
knotc_LDADD = libknotd.la
knot1to2_LDADD = libknot-internal.la libcontrib.la

####################################
# Optional Knot DNS Daemon modules #
####################################

if HAVE_DNSTAP
libknotd_la_SOURCES +=				\
	knot/modules/dnstap.c			\
	knot/modules/dnstap.h
libknotd_la_CPPFLAGS += $(DNSTAP_CFLAGS)
libknotd_la_LIBADD += $(DNSTAP_LIBS) contrib/dnstap/libdnstap.la
endif # HAVE_DNSTAP

if HAVE_ROSEDB
libknotd_la_SOURCES +=				\
	knot/modules/rosedb.c			\
	knot/modules/rosedb.h
endif # HAVE_ROSEDB

# Create storage and run-time directories
install-data-hook:
	$(INSTALL) -d $(DESTDIR)/@config_dir@
	$(INSTALL) -d $(DESTDIR)/@run_dir@
	$(INSTALL) -d $(DESTDIR)/@storage_dir@

endif # HAVE_DAEMON

######################
# Knot DNS Utilities #
######################

if HAVE_UTILS

bin_PROGRAMS = kdig khost knsupdate
noinst_LTLIBRARIES += libknotus.la

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
	utils/common/sign.c			\
	utils/common/sign.h			\
	utils/common/strtonum.h			\
	utils/common/token.c			\
	utils/common/token.h

libknotus_la_CPPFLAGS = $(AM_CPPFLAGS) $(libidn_CFLAGS)
libknotus_la_LDFLAGS = $(AM_LDFLAGS) $(libidn_LIBS)
libknotus_la_LIBADD = libcontrib.la libknot.la

# bin programs
kdig_LDADD       = $(libidn_LIBS) libknotus.la
khost_LDADD      = $(libidn_LIBS) libknotus.la
knsupdate_LDADD  = zscanner/libzscanner.la libknotus.la

#######################################
# Optional Knot DNS Utilities modules #
#######################################

if HAVE_DNSTAP
kdig_LDADD         += $(DNSTAP_LIBS) contrib/dnstap/libdnstap.la
khost_LDADD        += $(DNSTAP_LIBS) contrib/dnstap/libdnstap.la
endif # HAVE_DNSTAP

if HAVE_ROSEDB
bin_PROGRAMS += rosedb_tool
rosedb_tool_SOURCES = knot/modules/rosedb_tool.c
rosedb_tool_LDADD = libknotd.la
endif # HAVE_ROSEDB

endif # HAVE_UTILS
