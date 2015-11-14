ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
SUBDIRS = zscanner dnstap .

sbin_PROGRAMS = knotc knotd
bin_PROGRAMS = kdig khost knsupdate knsec3hash
lib_LTLIBRARIES = libknot.la
noinst_LTLIBRARIES = libknotd.la libknots.la libknotus.la libknotcs.la

# $(YACC) will generate header file
AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-DCONFIG_DIR='"${config_dir}"' \
	-DSTORAGE_DIR='"${storage_dir}"' \
	-DRUN_DIR='"${run_dir}"'
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = $(CODE_COVERAGE_LDFLAGS)
AM_YFLAGS = -d
libknotd_la_YFLAGS = -pcf_ -d
libknotd_la_LFLAGS = # TODO: reentrant parser, prefix

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

kdig_SOURCES =					\
	utils/dig/dig_exec.c			\
	utils/dig/dig_exec.h			\
	utils/dig/dig_main.c			\
	utils/dig/dig_params.c			\
	utils/dig/dig_params.h

khost_SOURCES =					\
	utils/dig/dig_exec.c			\
	utils/dig/dig_exec.h			\
	utils/dig/dig_params.c			\
	utils/dig/dig_params.h			\
	utils/host/host_main.c			\
	utils/host/host_params.c		\
	utils/host/host_params.h

knsupdate_SOURCES =				\
	utils/nsupdate/nsupdate_exec.c		\
	utils/nsupdate/nsupdate_exec.h		\
	utils/nsupdate/nsupdate_main.c		\
	utils/nsupdate/nsupdate_params.c	\
	utils/nsupdate/nsupdate_params.h

knsec3hash_SOURCES =				\
	utils/nsec3hash/nsec3hash_main.c

# static: shared (not in libknot)
libknots_la_SOURCES =				\
	common-knot/array-sort.h		\
	common-knot/binsearch.h			\
	common-knot/evsched.c			\
	common-knot/evsched.h			\
	common-knot/fdset.c			\
	common-knot/fdset.h			\
	common-knot/hattrie/hat-trie.c		\
	common-knot/hattrie/hat-trie.h		\
	common-knot/hattrie/murmurhash3.c	\
	common-knot/hattrie/murmurhash3.h	\
	common-knot/heap.c			\
	common-knot/heap.h			\
	common-knot/hex.c			\
	common-knot/hex.h			\
	common-knot/hhash.c			\
	common-knot/hhash.h			\
	common-knot/lists.c			\
	common-knot/lists.h			\
	common-knot/print.c			\
	common-knot/print.h			\
	common-knot/ref.c			\
	common-knot/ref.h			\
	common-knot/sockaddr.c			\
	common-knot/sockaddr.h			\
	common-knot/strlcat.c			\
	common-knot/strlcat.h			\
	common-knot/strlcpy.c			\
	common-knot/strlcpy.h			\
	common-knot/strtonum.h			\
	common-knot/trim.h

# static: common shared (also in libknot)
libknotcs_la_SOURCES =				\
	common/base32hex.c			\
	common/base32hex.h			\
	common/base64.c				\
	common/base64.h				\
	common/debug.h				\
	common/errors.c				\
	common/errors.h				\
	common/getline.c			\
	common/getline.h			\
	common/mem.c				\
	common/mem.h				\
	common/mempool.c			\
	common/mempool.h			\
	common/namedb/namedb.h			\
	common/namedb/namedb_lmdb.h		\
	common/namedb/namedb_lmdb.c		\
	common/namedb/namedb_trie.h		\
	common/namedb/namedb_trie.c		\
	common/log.c				\
	common/log.h

# static: utilities shared
libknotus_la_SOURCES =				\
	utils/common/exec.c			\
	utils/common/exec.h			\
	utils/common/msg.c			\
	utils/common/msg.h			\
	utils/common/netio.c			\
	utils/common/netio.h			\
	utils/common/params.c			\
	utils/common/params.h			\
	utils/common/resolv.c			\
	utils/common/resolv.h			\
	utils/common/token.c			\
	utils/common/token.h

# dynamic: libknot
libknot_la_LDFLAGS =				\
	$(AM_LDFLAGS)				\
	-version-info 0:1:0			\
	-export-symbols-regex '^(knot|KNOT|rrset|tsig|zone|mm)_'

libknot_la_SOURCES =				\
	libknot/binary.c			\
	libknot/binary.h			\
	libknot/common.h			\
	libknot/consts.c			\
	libknot/consts.h			\
	libknot/consts.h			\
	libknot/descriptor.c			\
	libknot/descriptor.h			\
	libknot/dname.c				\
	libknot/dname.h				\
	libknot/dnssec/config.h			\
	libknot/dnssec/crypto.c			\
	libknot/dnssec/crypto.h			\
	libknot/dnssec/key.c			\
	libknot/dnssec/key.h			\
	libknot/dnssec/bitmap.h			\
	libknot/dnssec/policy.c			\
	libknot/dnssec/policy.h			\
	libknot/dnssec/random.h			\
	libknot/dnssec/rrset-sign.c		\
	libknot/dnssec/rrset-sign.h		\
	libknot/dnssec/sig0.c			\
	libknot/dnssec/sig0.h			\
	libknot/dnssec/sign.c			\
	libknot/dnssec/sign.h			\
	libknot/errcode.c			\
	libknot/errcode.h			\
	libknot/libknot.h			\
	libknot/mempattern.c			\
	libknot/mempattern.h			\
	libknot/packet/compr.c			\
	libknot/packet/compr.h			\
	libknot/packet/pkt.c			\
	libknot/packet/pkt.h			\
	libknot/packet/rrset-wire.c		\
	libknot/packet/rrset-wire.h		\
	libknot/packet/wire.h			\
	libknot/processing/process.c		\
	libknot/processing/process.h		\
	libknot/rrtype/dnskey.h			\
	libknot/rrtype/naptr.c			\
	libknot/rrtype/naptr.h			\
	libknot/rrtype/nsec.h			\
	libknot/rrtype/nsec.h			\
	libknot/rrtype/nsec3.c			\
	libknot/rrtype/nsec3.h			\
	libknot/rrtype/nsec3param.c		\
	libknot/rrtype/nsec3param.h		\
	libknot/rrtype/opt.c			\
	libknot/rrtype/opt.h			\
	libknot/rrtype/rdname.h			\
	libknot/rrtype/rrsig.h			\
	libknot/rrtype/soa.h			\
	libknot/rrtype/tsig.c			\
	libknot/rrtype/tsig.h			\
	libknot/rrset-dump.c			\
	libknot/rrset-dump.h			\
	libknot/rdata.c				\
	libknot/rdata.h				\
	libknot/rdataset.c			\
	libknot/rdataset.h			\
	libknot/rrset.c				\
	libknot/rrset.h				\
	libknot/tsig-op.c			\
	libknot/tsig-op.h			\
	libknot/util/endian.h			\
	libknot/util/tolower.c			\
	libknot/util/tolower.h			\
	libknot/util/utils.c			\
	libknot/util/utils.h

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
	knot/dnssec/nsec-chain.c		\
	knot/dnssec/nsec-chain.h		\
	knot/dnssec/nsec3-chain.c		\
	knot/dnssec/nsec3-chain.h		\
	knot/dnssec/zone-events.c		\
	knot/dnssec/zone-events.h		\
	knot/dnssec/zone-keys.c			\
	knot/dnssec/zone-keys.h			\
	knot/dnssec/zone-nsec.c			\
	knot/dnssec/zone-nsec.h			\
	knot/dnssec/zone-sign.c			\
	knot/dnssec/zone-sign.h			\
	knot/knot.h				\
	knot/nameserver/axfr.c			\
	knot/nameserver/axfr.h			\
	knot/nameserver/chaos.c			\
	knot/nameserver/chaos.h			\
	knot/nameserver/capture.c		\
	knot/nameserver/capture.h		\
	knot/nameserver/internet.c		\
	knot/nameserver/internet.h		\
	knot/nameserver/ixfr.c			\
	knot/nameserver/ixfr.h			\
	knot/nameserver/nsec_proofs.c		\
	knot/nameserver/nsec_proofs.h		\
	knot/nameserver/process_query.c		\
	knot/nameserver/process_query.h		\
	knot/nameserver/process_answer.c	\
	knot/nameserver/process_answer.h	\
	knot/nameserver/requestor.c		\
	knot/nameserver/requestor.h		\
	knot/nameserver/query_module.c		\
	knot/nameserver/query_module.h		\
	knot/nameserver/update.c		\
	knot/nameserver/update.h		\
	knot/nameserver/notify.c		\
	knot/nameserver/notify.h		\
	knot/nameserver/tsig_ctx.c		\
	knot/nameserver/tsig_ctx.h		\
	knot/modules/synth_record.c		\
	knot/modules/synth_record.h		\
	knot/other/debug.h			\
	knot/server/dthreads.c			\
	knot/server/dthreads.h			\
	knot/server/journal.c			\
	knot/server/journal.h			\
	knot/server/rrl.c			\
	knot/server/rrl.h			\
	knot/server/server.c			\
	knot/server/server.h			\
	knot/server/net.c			\
	knot/server/net.h			\
	knot/server/tcp-handler.c		\
	knot/server/tcp-handler.h		\
	knot/server/udp-handler.c		\
	knot/server/udp-handler.h		\
	knot/server/serialization.c		\
	knot/server/serialization.h		\
	knot/updates/acl.c			\
	knot/updates/acl.h			\
	knot/updates/changesets.c		\
	knot/updates/changesets.h		\
	knot/updates/ddns.c			\
	knot/updates/ddns.h			\
	knot/updates/apply.c			\
	knot/updates/apply.h			\
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
	knot/zone/timers.c			\
	knot/zone/timers.h			\
	knot/zone/zone-diff.c			\
	knot/zone/zone-diff.h			\
	knot/zone/zone-dump.c			\
	knot/zone/zone-dump.h			\
	knot/zone/zone-tree.c			\
	knot/zone/zone-tree.h			\
	knot/zone/zone.c			\
	knot/zone/zone.h			\
	knot/zone/zone-load.c			\
	knot/zone/zone-load.h			\
	knot/zone/zonedb.c			\
	knot/zone/zonedb.h			\
	knot/zone/zonedb-load.c			\
	knot/zone/zonedb-load.h			\
	knot/zone/zonefile.c			\
	knot/zone/zonefile.h

# libraries
libknot_la_LIBADD  = libknotcs.la zscanner/libzscanner.la
libknotd_la_LIBADD = libknots.la libknotcs.la libknot.la
libknotus_la_LIBADD = libknots.la libknotcs.la libknot.la
libknotd_la_CPPFLAGS = $(AM_CPPFLAGS) $(lmdb_CFLAGS)
libknotd_la_LDFLAGS = $(AM_LDFLAGS) $(lmdb_LIBS)
libknotus_la_CPPFLAGS = $(AM_CPPFLAGS) $(libidn_CFLAGS)
libknotus_la_LDFLAGS = $(AM_LDFLAGS) $(libidn_LIBS)
libknotcs_la_CPPFLAGS = $(AM_CPPFLAGS) $(systemd_CFLAGS) $(lmdb_CFLAGS)
libknotcs_la_LDFLAGS = $(AM_LDFLAGS) $(systemd_LIBS) $(lmdb_LIBS)

# sbin programs
knotd_LDADD = libknot.la libknotd.la $(systemd_LIBS) $(lmdb_LIBS)
knotc_LDADD = libknot.la libknotd.la

# bin programs
BIN_LIBS = libknotus.la libknots.la
kdig_LDADD       = $(BIN_LIBS) $(libidn_LIBS)
khost_LDADD      = $(BIN_LIBS) $(libidn_LIBS)
knsupdate_LDADD  = $(BIN_LIBS) zscanner/libzscanner.la
knsec3hash_LDADD = $(BIN_LIBS)

if HAVE_DNSTAP
libknotd_la_SOURCES +=				\
	knot/modules/dnstap.c			\
	knot/modules/dnstap.h

kdig_LDADD         += dnstap/libdnstap.la
khost_LDADD        += dnstap/libdnstap.la
libknotd_la_LIBADD += dnstap/libdnstap.la
endif

if HAVE_ROSEDB
libknotd_la_SOURCES +=				\
	knot/modules/rosedb.c			\
	knot/modules/rosedb.h
bin_PROGRAMS += rosedb_tool
rosedb_tool_SOURCES = knot/modules/rosedb_tool.c
rosedb_tool_LDADD = libknot.la libknotd.la
endif # HAVE_ROSEDB

# Create storage and run-time directories
install-data-hook:
	$(INSTALL) -d $(DESTDIR)/@config_dir@
	$(INSTALL) -d $(DESTDIR)/@run_dir@
	$(INSTALL) -d $(DESTDIR)/@storage_dir@
