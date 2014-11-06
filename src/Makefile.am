ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
SUBDIRS = zscanner dnstap .

sbin_PROGRAMS = knotc knotd
bin_PROGRAMS = kdig khost knsupdate knsec3hash
lib_LTLIBRARIES = libknot.la
noinst_LTLIBRARIES = libknotd.la libknots.la libknotus.la libknotcs.la

# $(YACC) will generate header file
AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h	\
	-DCONFIG_DIR='"${config_dir}"'		\
	-DSTORAGE_DIR='"${storage_dir}"'	\
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
	common-knot/crc.h			\
	common-knot/evsched.c			\
	common-knot/evsched.h			\
	common-knot/fdset.c			\
	common-knot/fdset.h			\
	common-knot/heap.c			\
	common-knot/heap.h			\
	common-knot/hex.c			\
	common-knot/hex.h			\
	common-knot/ref.c			\
	common-knot/ref.h			\
	common-knot/strlcat.c			\
	common-knot/strlcat.h			\
	common-knot/strtonum.h			\
	common-knot/trim.h

# static: common shared (also in libknot)
libknotcs_la_SOURCES =				\
	libknot/internal/array-sort.h		\
	libknot/internal/base32hex.c		\
	libknot/internal/base32hex.h		\
	libknot/internal/base64.c		\
	libknot/internal/base64.h		\
	libknot/internal/binsearch.h		\
	libknot/internal/debug.h		\
	libknot/internal/errors.c		\
	libknot/internal/errors.h		\
	libknot/internal/getline.c		\
	libknot/internal/getline.h		\
	libknot/internal/hhash.c		\
	libknot/internal/hhash.h		\
	libknot/internal/lists.c		\
	libknot/internal/lists.h		\
	libknot/internal/log.c			\
	libknot/internal/log.h			\
	libknot/internal/macros.h		\
	libknot/internal/mem.c			\
	libknot/internal/mem.h			\
	libknot/internal/mempattern.c		\
	libknot/internal/mempattern.h		\
	libknot/internal/mempool.c		\
	libknot/internal/mempool.h		\
	libknot/internal/namedb/namedb.h	\
	libknot/internal/namedb/namedb_lmdb.c	\
	libknot/internal/namedb/namedb_lmdb.h	\
	libknot/internal/namedb/namedb_trie.c	\
	libknot/internal/namedb/namedb_trie.h	\
	libknot/internal/net.c			\
	libknot/internal/net.h			\
	libknot/internal/print.c		\
	libknot/internal/print.h		\
	libknot/internal/sockaddr.c		\
	libknot/internal/sockaddr.h		\
	libknot/internal/strlcpy.c		\
	libknot/internal/strlcpy.h		\
	libknot/internal/trie/hat-trie.c	\
	libknot/internal/trie/hat-trie.h	\
	libknot/internal/trie/murmurhash3.c	\
	libknot/internal/trie/murmurhash3.h

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
	-version-info 0:1:0

libknot_la_SOURCES =				\
	libknot/binary.c			\
	libknot/binary.h			\
	libknot/consts.c			\
	libknot/consts.h			\
	libknot/consts.h			\
	libknot/descriptor.c			\
	libknot/descriptor.h			\
	libknot/dname.c				\
	libknot/dname.h				\
	libknot/dnssec/bitmap.h			\
	libknot/dnssec/config.h			\
	libknot/dnssec/crypto.c			\
	libknot/dnssec/crypto.h			\
	libknot/dnssec/key.c			\
	libknot/dnssec/key.h			\
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
	libknot/packet/compr.c			\
	libknot/packet/compr.h			\
	libknot/packet/pkt.c			\
	libknot/packet/pkt.h			\
	libknot/packet/rrset-wire.c		\
	libknot/packet/rrset-wire.h		\
	libknot/packet/wire.h			\
	libknot/processing/layer.c		\
	libknot/processing/layer.h		\
	libknot/processing/overlay.c		\
	libknot/processing/overlay.h		\
	libknot/processing/requestor.c		\
	libknot/processing/requestor.h		\
	libknot/rdata.c				\
	libknot/rdata.h				\
	libknot/rdataset.c			\
	libknot/rdataset.h			\
	libknot/rrset-dump.c			\
	libknot/rrset-dump.h			\
	libknot/rrset.c				\
	libknot/rrset.h				\
	libknot/rrtype/aaaa.h			\
	libknot/rrtype/dnskey.h			\
	libknot/rrtype/naptr.h			\
	libknot/rrtype/nsec.h			\
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
	libknot/tsig-op.c			\
	libknot/tsig-op.h			\
	libknot/internal/endian.h		\
	libknot/internal/tolower.c		\
	libknot/internal/tolower.h		\
	libknot/internal/utils.c		\
	libknot/internal/utils.h

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
	knot/other/debug.h			\
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

# Create storage and run-time directories
install-data-hook:
	$(INSTALL) -d $(DESTDIR)/@config_dir@
	$(INSTALL) -d $(DESTDIR)/@run_dir@
	$(INSTALL) -d $(DESTDIR)/@storage_dir@
