ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
SUBDIRS = zscanner dnstap .

sbin_PROGRAMS = knotc knotd
bin_PROGRAMS = kdig khost knsupdate knsec3hash
lib_LTLIBRARIES = libknot.la
noinst_LTLIBRARIES = libknotd.la libknots.la libknotus.la

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

# static: shared
libknots_la_SOURCES =				\
	common/array-sort.h			\
	common/base32hex.c			\
	common/base32hex.h			\
	common/base64.c				\
	common/base64.h				\
	common/binsearch.h			\
	common/crc.h				\
	common/debug.h				\
	common/descriptor.c			\
	common/descriptor.h			\
	common/errcode.c			\
	common/errcode.h			\
	common/errors.c				\
	common/errors.h				\
	common/evsched.c			\
	common/evsched.h			\
	common/fdset.c				\
	common/fdset.h				\
	common/getline.c			\
	common/getline.h			\
	common/hattrie/hat-trie.c		\
	common/hattrie/hat-trie.h		\
	common/hattrie/murmurhash3.c		\
	common/hattrie/murmurhash3.h		\
	common/heap.c				\
	common/heap.h				\
	common/hex.c				\
	common/hex.h				\
	common/hhash.c				\
	common/hhash.h				\
	common/lists.c				\
	common/lists.h				\
	common/log.c				\
	common/log.h				\
	common/memdup.h				\
	common/mempattern.c			\
	common/mempattern.h			\
	common/mempool.c			\
	common/mempool.h			\
	common/print.c				\
	common/print.h				\
	common/ref.c				\
	common/ref.h				\
	common/slab/alloc-common.h		\
	common/slab/slab.c			\
	common/slab/slab.h			\
	common/sockaddr.c			\
	common/sockaddr.h			\
	common/strtonum.h

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
	-export-symbols-regex '^(knot|KNOT|rrset|tsig|zone)_'

libknot_la_SOURCES =				\
	libknot/binary.c			\
	libknot/binary.h			\
	libknot/common.h			\
	libknot/consts.c			\
	libknot/consts.h			\
	libknot/consts.h			\
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
	libknot/edns.c				\
	libknot/edns.h				\
	libknot/libknot.h			\
	libknot/packet/compr.c			\
	libknot/packet/compr.h			\
	libknot/packet/pkt.c			\
	libknot/packet/pkt.h			\
	libknot/packet/wire.h			\
	libknot/processing/process.c		\
	libknot/processing/process.h		\
	libknot/rdata/rdname.h			\
	libknot/rdata/dnskey.h			\
	libknot/rdata/nsec.h			\
	libknot/rdata/nsec3.c			\
	libknot/rdata/nsec3.h			\
	libknot/rdata/nsec3param.h			\
	libknot/rdata/nsec3param.c			\
	libknot/rdata/nsec.h			\
	libknot/rdata/rrsig.h			\
	libknot/rdata/soa.h			\
	libknot/rdata/tsig.c				\
	libknot/rdata/tsig.h				\
	libknot/rrset-dump.c			\
	libknot/rrset-dump.h			\
	libknot/rdata.c				\
	libknot/rdata.h				\
	libknot/rdataset.c				\
	libknot/rdataset.h				\
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
	knot/conf/logconf.c			\
	knot/conf/logconf.h			\
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
	knot/nameserver/internet.c		\
	knot/nameserver/internet.h		\
	knot/nameserver/ixfr.c			\
	knot/nameserver/ixfr.h			\
	knot/nameserver/nsec_proofs.c		\
	knot/nameserver/nsec_proofs.h		\
	knot/nameserver/process_query.c		\
	knot/nameserver/process_query.h		\
	knot/nameserver/query_module.c		\
	knot/nameserver/query_module.h		\
	knot/nameserver/update.c		\
	knot/nameserver/update.h		\
	knot/modules/synth_record.c		\
	knot/modules/synth_record.h		\
	knot/other/debug.h			\
	knot/server/dthreads.c			\
	knot/server/dthreads.h			\
	knot/server/journal.c			\
	knot/server/journal.h			\
	knot/server/notify.c			\
	knot/server/notify.h			\
	knot/server/rrl.c			\
	knot/server/rrl.h			\
	knot/server/server.c			\
	knot/server/server.h			\
	knot/server/net.c				\
	knot/server/net.h				\
	knot/server/tcp-handler.c		\
	knot/server/tcp-handler.h		\
	knot/server/udp-handler.c		\
	knot/server/udp-handler.h		\
	knot/server/xfr-handler.c		\
	knot/server/xfr-handler.h		\
	knot/server/zone-load.c			\
	knot/server/zone-load.h			\
	knot/server/zones.c			\
	knot/server/zones.h			\
	knot/server/serialization.c		\
	knot/server/serialization.h		\
	knot/updates/acl.c			\
	knot/updates/acl.h			\
	knot/updates/changesets.c		\
	knot/updates/changesets.h		\
	knot/updates/ddns.c			\
	knot/updates/ddns.h			\
	knot/updates/xfr-in.c			\
	knot/updates/xfr-in.h			\
	knot/zone/estimator.c			\
	knot/zone/estimator.h			\
	knot/zone/node.c			\
	knot/zone/node.h			\
	knot/zone/semantic-check.c		\
	knot/zone/semantic-check.h		\
	knot/zone/zone-contents.c		\
	knot/zone/zone-contents.h		\
	knot/zone/zone-diff.c			\
	knot/zone/zone-diff.h			\
	knot/zone/zone-dump.c			\
	knot/zone/zone-dump.h			\
	knot/zone/zone-create.c			\
	knot/zone/zone-create.h			\
	knot/zone/zone-tree.c			\
	knot/zone/zone-tree.h			\
	knot/zone/zone.c			\
	knot/zone/zone.h			\
	knot/zone/zonedb.c			\
	knot/zone/zonedb.h

# libraries
libknot_la_LIBADD  = libknots.la zscanner/libzscanner.la
libknotd_la_LIBADD = libknots.la libknot.la

# sbin programs
knotd_LDADD = libknot.la libknotd.la
knotd_CPPFLAGS = $(AM_CPPFLAGS) ${systemd_daemon_CFLAGS}
knotd_LDFLAGS = $(AM_LDFLAGS) ${systemd_daemon_LIBS}

knotc_LDADD = libknot.la libknotd.la

# bin programs
kdig_LDADD       = libknotus.la libknots.la libknot.la
khost_LDADD      = libknotus.la libknots.la libknot.la
knsupdate_LDADD  = libknotus.la libknots.la libknot.la zscanner/libzscanner.la
knsec3hash_LDADD = libknotus.la libknots.la libknot.la

if HAVE_DNSTAP
kdig_LDADD	+= dnstap/libdnstap.la
khost_LDADD	+= dnstap/libdnstap.la
endif

# Create storage and run-time directories
install-data-hook:
	$(INSTALL) -d $(DESTDIR)/@config_dir@
	$(INSTALL) -d $(DESTDIR)/@run_dir@
	$(INSTALL) -d $(DESTDIR)/@storage_dir@
