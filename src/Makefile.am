ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
SUBDIRS = zscanner .

sbin_PROGRAMS = knotc knotd
bin_PROGRAMS = kdig khost knsupdate knsec3hash
noinst_LTLIBRARIES = libknot.la libknotd.la libknots.la

# $(YACC) will generate header file
AM_CPPFLAGS = -DCONFIG_DIR='"${config_dir}"' -DSTORAGE_DIR='"${storage_dir}"' \
	      -DRUN_DIR='"${run_dir}"'
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
	utils/common/msg.h			\
	utils/common/msg.c			\
	utils/common/exec.c			\
	utils/common/exec.h			\
	utils/common/params.c			\
	utils/common/params.h			\
	utils/common/resolv.c			\
	utils/common/resolv.h			\
	utils/common/netio.c			\
	utils/common/netio.h			\
	utils/common/token.c			\
	utils/common/token.h			\
	utils/dig/dig_main.c			\
	utils/dig/dig_params.c			\
	utils/dig/dig_params.h			\
	utils/dig/dig_exec.c			\
	utils/dig/dig_exec.h

khost_SOURCES =					\
	utils/common/msg.h			\
	utils/common/msg.c			\
	utils/common/exec.c			\
	utils/common/exec.h			\
	utils/common/params.c			\
	utils/common/params.h			\
	utils/common/resolv.c			\
	utils/common/resolv.h			\
	utils/common/netio.c			\
	utils/common/netio.h			\
	utils/common/token.c			\
	utils/common/token.h			\
	utils/host/host_main.c			\
	utils/dig/dig_params.c			\
	utils/dig/dig_params.h			\
	utils/host/host_params.c		\
	utils/host/host_params.h		\
	utils/dig/dig_exec.c			\
	utils/dig/dig_exec.h

knsupdate_SOURCES =				\
	utils/common/msg.h			\
	utils/common/msg.c			\
	utils/common/params.c			\
	utils/common/params.h			\
	utils/common/resolv.c			\
	utils/common/resolv.h			\
	utils/common/netio.c			\
	utils/common/netio.h			\
	utils/common/token.c			\
	utils/common/token.h			\
	utils/common/exec.c			\
	utils/common/exec.h			\
	utils/nsupdate/nsupdate_main.c		\
	utils/nsupdate/nsupdate_params.h	\
	utils/nsupdate/nsupdate_params.c	\
	utils/nsupdate/nsupdate_exec.h		\
	utils/nsupdate/nsupdate_exec.c

knsec3hash_SOURCES =				\
	utils/common/msg.h			\
	utils/common/msg.c			\
	utils/common/netio.h			\
	utils/common/netio.c			\
	utils/common/resolv.h			\
	utils/common/resolv.c			\
	utils/common/params.h			\
	utils/common/params.c			\
	utils/nsec3hash/nsec3hash_main.c

libknot_la_SOURCES =				\
	libknot/common.h			\
	libknot/consts.h			\
	libknot/consts.c			\
	libknot/util/utils.c			\
	libknot/util/debug.c			\
	libknot/util/debug.h			\
	libknot/util/utils.h			\
	libknot/util/tolower.h			\
	libknot/util/tolower.c			\
	libknot/util/wire.h			\
	libknot/util/endian.h			\
	libknot/packet/query.c			\
	libknot/packet/response.c		\
	libknot/packet/packet.c			\
	libknot/packet/packet.h			\
	libknot/packet/query.h			\
	libknot/packet/response.h		\
	libknot/zone/zone.c			\
	libknot/zone/zone-contents.c		\
	libknot/zone/zone-tree.c		\
	libknot/zone/zone-tree.h		\
	libknot/zone/node.h			\
	libknot/zone/zone.h			\
	libknot/zone/zone-contents.h		\
	libknot/zone/zonedb.c			\
	libknot/zone/zonedb.h			\
	libknot/zone/node.c			\
	libknot/zone/zone-diff.h		\
	libknot/zone/zone-diff.c		\
	libknot/nameserver/name-server.h	\
	libknot/nameserver/name-server.c	\
	libknot/nameserver/chaos.h		\
	libknot/nameserver/chaos.c		\
	libknot/updates/changesets.h		\
	libknot/updates/changesets.c		\
	libknot/updates/xfr-in.h		\
	libknot/updates/xfr-in.c		\
	libknot/updates/ddns.h			\
	libknot/updates/ddns.c			\
	libknot/dname.c				\
	libknot/consts.h			\
	libknot/edns.h				\
	libknot/edns.c				\
	libknot/libknot.h			\
	libknot/dname.h				\
	libknot/rdata.h				\
	libknot/rrset.h				\
	libknot/rrset.c				\
	libknot/rrset-dump.h			\
	libknot/rrset-dump.c			\
	libknot/tsig.h				\
	libknot/tsig.c				\
	libknot/tsig-op.h			\
	libknot/tsig-op.c			\
	libknot/binary.h			\
	libknot/binary.c			\
	libknot/dnssec/config.h			\
	libknot/dnssec/crypto.c			\
	libknot/dnssec/crypto.h			\
	libknot/dnssec/key.c			\
	libknot/dnssec/key.h			\
	libknot/dnssec/nsec-bitmap.h		\
	libknot/dnssec/nsec3.c			\
	libknot/dnssec/nsec3.h			\
	libknot/dnssec/policy.h			\
	libknot/dnssec/random.h			\
	libknot/dnssec/rrset-sign.c		\
	libknot/dnssec/rrset-sign.h		\
	libknot/dnssec/sig0.c			\
	libknot/dnssec/sig0.h			\
	libknot/dnssec/sign.c			\
	libknot/dnssec/sign.h			\
	libknot/dnssec/zone-events.c		\
	libknot/dnssec/zone-events.h		\
	libknot/dnssec/zone-keys.c		\
	libknot/dnssec/zone-keys.h		\
	libknot/dnssec/zone-nsec.c		\
	libknot/dnssec/zone-nsec.h		\
	libknot/dnssec/zone-sign.c		\
	libknot/dnssec/zone-sign.h

libknots_la_SOURCES =				\
	common/slab/slab.c			\
	common/slab/slab.h			\
	common/slab/alloc-common.h		\
	common/array-sort.h			\
	common/atomic.h				\
	common/binsearch.h			\
	common/memdup.h				\
	common/mempattern.h			\
	common/mempattern.c			\
	common/descriptor.h			\
	common/descriptor.c			\
	common/lists.c				\
	common/base64.c				\
	common/base64.h				\
	common/lists.h				\
	common/heap.h				\
	common/heap.c				\
	common/print.c				\
	common/print.h				\
	common/base32hex.c			\
	common/base32hex.h			\
	common/evqueue.h			\
	common/evqueue.c			\
	common/evsched.h			\
	common/evsched.c			\
	common/acl.h				\
	common/acl.c				\
	common/sockaddr.h			\
	common/sockaddr.c			\
	common/crc.h				\
	common/ref.h				\
	common/ref.c				\
	common/errors.h				\
	common/errors.c				\
	common/errcode.h			\
	common/errcode.c			\
	common/fdset.h				\
	common/fdset.c				\
	common/getline.h			\
	common/getline.c			\
	common/log.c				\
	common/log.h				\
	common/mempool.c			\
	common/mempool.h			\
	common/hhash.c				\
	common/hhash.h				\
	common/hattrie/hat-trie.c		\
	common/hattrie/hat-trie.h		\
	common/hattrie/murmurhash3.c		\
	common/hattrie/murmurhash3.h		\
	common/hex.c				\
	common/hex.h				\
	common/strtonum.h

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
	knot/knot.h				\
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
	knot/server/socket.c			\
	knot/server/socket.h			\
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
	knot/stat/gatherer.c			\
	knot/stat/gatherer.h			\
	knot/stat/stat-common.h			\
	knot/stat/stat.c			\
	knot/stat/stat.h			\
	knot/zone/estimator.c			\
	knot/zone/estimator.h			\
	knot/zone/semantic-check.c		\
	knot/zone/semantic-check.h		\
	knot/zone/zone-dump.c			\
	knot/zone/zone-dump.h			\
	knot/zone/zone-load.c			\
	knot/zone/zone-load.h

libknotd_la_LIBADD = libknot.la libknots.la @LIBOBJS@
libknots_la_LIBADD = zscanner/libzscanner.la @LIBOBJS@
knotd_LDADD = libknotd.la libknot.la libknots.la @LIBOBJS@
knotc_LDADD = libknotd.la libknot.la libknots.la @LIBOBJS@
kdig_LDADD = libknotd.la libknot.la libknots.la @LIBOBJS@
khost_LDADD = libknotd.la libknot.la libknots.la @LIBOBJS@
knsupdate_LDADD = libknotd.la libknot.la libknots.la zscanner/libzscanner.la @LIBOBJS@
knsec3hash_LDADD = libknot.la libknots.la @LIBOBJS@

# Create storage and run-time directories
install-data-hook:
	$(INSTALL) -d $(DESTDIR)/@config_dir@
	$(INSTALL) -d $(DESTDIR)/@run_dir@
	$(INSTALL) -d $(DESTDIR)/@storage_dir@
