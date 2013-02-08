ACLOCAL_AMFLAGS = -I ../m4
libexec_PROGRAMS = knot-zcompile unittests unittests-zcompile unittests-xfr unittests-zscanner kdig khost knsupdate
sbin_PROGRAMS = knotc knotd
dist_man_MANS = knot.conf.5 knotc.8 knotd.8

# $(YACC) will generate header file
AM_CFLAGS = -Wall -Ilibknot -DLIBEXECDIR='"$(libexecdir)"' -DSYSCONFDIR='"$(sysconfdir)"' -DSBINDIR='"$(sbindir)"'
AM_YFLAGS = -d
libknotd_la_YFLAGS = -pcf_ -d
libknotd_la_LFLAGS = # TODO: reentrant parser, prefix

BUILT_SOURCES =					\
	tests/sample_conf.rc			\
	zparser.h				\
	zparser.c				\
	zlexer.c				\
	libknotd_la-cf-lex.c			\
	libknotd_la-cf-parse.c			\
	libknotd_la-cf-parse.h

CLEANFILES =					\
	tests/sample_conf.rc			\
	zparser.h				\
	zparser.c				\
	zlexer.c				\
	libknotd_la-cf-lex.c			\
	libknotd_la-cf-parse.c			\
	libknotd_la-cf-parse.h

knotc_SOURCES =					\
	knot/ctl/knotc_main.c

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
	utils/common/rr-serialize.h		\
	utils/common/rr-serialize.c		\
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
	utils/common/rr-serialize.h		\
	utils/common/rr-serialize.c		\
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
	utils/common/rr-serialize.h		\
	utils/common/rr-serialize.c		\
	utils/common/exec.c			\
	utils/common/exec.h			\
	utils/nsupdate/nsupdate_main.c		\
	utils/nsupdate/nsupdate_params.c	\
	utils/nsupdate/nsupdate_params.h	\
	utils/nsupdate/nsupdate_exec.c		\
	utils/nsupdate/nsupdate_exec.h

knot_zcompile_SOURCES =				\
	zcompile/zcompile_main.c		\
	zcompile/zcompile-error.c		\
	zcompile/parser-util.h			\
	zcompile/parser-descriptor.h		\
	zcompile/zparser.y			\
	zcompile/zlexer.l			\
	zcompile/zcompile.c			\
	zcompile/parser-util.c			\
	zcompile/parser-descriptor.c

unittests_SOURCES =				\
	tests/common/acl_tests.c		\
	tests/common/acl_tests.h		\
	tests/common/base32hex_tests.c		\
	tests/common/base32hex_tests.h		\
	tests/common/base64_tests.c		\
	tests/common/base64_tests.h		\
	tests/common/events_tests.c		\
	tests/common/events_tests.h		\
	tests/common/skiplist_tests.c		\
	tests/common/skiplist_tests.h		\
	tests/common/slab_tests.c		\
	tests/common/slab_tests.h		\
	tests/common/fdset_tests.c		\
	tests/common/fdset_tests.h		\
	tests/knot/conf_tests.c			\
	tests/knot/conf_tests.h			\
	tests/knot/dthreads_tests.c		\
	tests/knot/dthreads_tests.h		\
	tests/knot/journal_tests.c		\
	tests/knot/journal_tests.h		\
	tests/knot/server_tests.c		\
	tests/knot/server_tests.h		\
	tests/libknot/wire_tests.c		\
	tests/libknot/wire_tests.h		\
	tests/unittests_main.c

unittests_zcompile_SOURCES =			\
	zcompile/parser-util.h			\
	zcompile/parser-descriptor.h		\
	zcompile/zcompile-error.c		\
	zcompile/zparser.y			\
	zcompile/zlexer.l			\
	zcompile/zcompile.c			\
	zcompile/parser-util.c			\
	zcompile/parser-descriptor.c		\
	zcompile/tests/unittests_zp_main.c

unittests_xfr_SOURCES = 			\
	tests/xfr_tests.c			\
	tests/xfr_tests.h

nodist_unittests_SOURCES =			\
	tests/libknot/parsed_data.rc		\
	tests/libknot/raw_data_queries.rc	\
	tests/libknot/raw_data.rc		\
	tests/libknot/parsed_data_queries.rc	\
	tests/sample_conf.rc

knotd_SOURCES =					\
	knot/main.c

noinst_LTLIBRARIES = libknot.la libknotd.la libknots.la libzscanner.la

libknot_la_SOURCES =				\
	libknot/util/utils.c			\
	libknot/util/debug.c			\
	libknot/util/debug.h			\
	libknot/util/utils.h			\
	libknot/util/descriptor.c		\
	libknot/util/tolower.h			\
	libknot/util/tolower.c			\
	libknot/util/descriptor.h		\
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
	libknot/zone/dname-table.h		\
	libknot/zone/dname-table.c		\
	libknot/zone/zone-diff.h		\
	libknot/zone/zone-diff.c		\
	libknot/hash/hash-functions.c		\
	libknot/hash/cuckoo-hash-table.c	\
	libknot/hash/universal-system.c		\
	libknot/hash/universal-system.h		\
	libknot/hash/cuckoo-hash-table.h	\
	libknot/hash/hash-functions.h		\
	libknot/nameserver/name-server.h	\
	libknot/nameserver/name-server.c	\
	libknot/updates/changesets.h		\
	libknot/updates/changesets.c		\
	libknot/updates/xfr-in.h		\
	libknot/updates/xfr-in.c		\
	libknot/updates/ddns.h			\
	libknot/updates/ddns.c			\
	libknot/edns.c				\
	libknot/rrset.c				\
	libknot/dname.c				\
	libknot/rdata.c				\
	libknot/nsec3.c				\
	libknot/consts.h			\
	libknot/edns.h				\
	libknot/rdata.h				\
	libknot/libknot.h			\
	libknot/dname.h				\
	libknot/rrset.h				\
	libknot/nsec3.h				\
	libknot/tsig.h				\
	libknot/tsig.c				\
	libknot/tsig-op.h			\
	libknot/tsig-op.c

libknots_la_SOURCES =				\
	common/slab/slab.c			\
	common/slab/slab.h			\
	common/libtap/tap.c			\
	common/libtap/tap.h			\
	common/libtap/tap_unit.h		\
	common/mempattern.h			\
	common/mempattern.c			\
	common/descriptor_new.h			\
	common/descriptor_new.c			\
	common/lists.c				\
	common/base64.c				\
	common/base64.h				\
	common/lists.h				\
	common/heap.h				\
	common/heap.c				\
	common/print.c				\
	common/print.h				\
	common/skip-list.c			\
	common/base32hex.c			\
	common/skip-list.h			\
	common/general-tree.h			\
	common/general-tree.c			\
	common/tree.h				\
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
	common/dSFMT.h				\
	common/dSFMT-params.h			\
	common/dSFMT-params521.h		\
	common/dSFMT.c				\
	common/prng.h				\
	common/prng.c				\
	common/fdset.h				\
	common/fdset.c				\
	common/fdset_poll.h			\
	common/fdset_poll.c			\
	common/fdset_kqueue.h			\
	common/fdset_kqueue.c			\
	common/fdset_epoll.h			\
	common/fdset_epoll.c			\
	common/log.c				\
	common/log.h

libknotd_la_SOURCES =				\
	knot/stat/gatherer.c			\
	knot/stat/stat.c			\
	knot/stat/gatherer.h			\
	knot/stat/stat.h			\
	knot/common.h				\
	knot/other/debug.h			\
	knot/conf/cf-parse.y			\
	knot/conf/cf-lex.l			\
	knot/conf/conf.c			\
	knot/conf/logconf.c			\
	knot/conf/logconf.h			\
	knot/conf/conf.h			\
	knot/ctl/process.c			\
	knot/ctl/process.h			\
	knot/ctl/remote.c			\
	knot/ctl/remote.h			\
	knot/server/dthreads.c			\
	knot/server/journal.c			\
	knot/server/socket.c			\
	knot/server/server.c			\
	knot/server/udp-handler.c		\
	knot/server/tcp-handler.c		\
	knot/server/xfr-handler.c		\
	knot/server/zones.c			\
	knot/server/socket.h			\
	knot/server/udp-handler.h		\
	knot/server/tcp-handler.h		\
	knot/server/xfr-handler.h		\
	knot/server/dthreads.h			\
	knot/server/journal.h			\
	knot/server/zones.h			\
	knot/server/notify.h			\
	knot/server/notify.c			\
	knot/server/zones.h			\
	knot/zone/zone-load.c			\
	knot/zone/zone-load.h			\
	knot/zone/semantic-check.c		\
	knot/zone/semantic-check.h		\
	knot/zone/zone-dump.c			\
	knot/zone/zone-dump-text.c		\
	knot/zone/zone-dump-text.h		\
	knot/zone/zone-dump.h			\
	knot/server/server.h

zscanner/scanner.c: zscanner/scanner.rl zscanner/scanner_body.rl
	$(RAGEL) -s -o zscanner/scanner.c zscanner/scanner.rl

unittests_zscanner_SOURCES =			\
	zscanner/test/zscanner_test.c		\
	zscanner/test/tests.h			\
	zscanner/test/tests.c			\
	zscanner/test/processing.h		\
	zscanner/test/processing.c

libzscanner_la_SOURCES =			\
	zscanner/file_loader.h			\
	zscanner/file_loader.c			\
	zscanner/scanner.h			\
	zscanner/scanner.c			\
	zscanner/scanner_functions.h		\
	zscanner/scanner_functions.c

libknotd_la_LIBADD = libknot.la libknots.la @LIBOBJS@
libknots_la_LIBADD = @LIBOBJS@
libzscanner_la_LIBADD = libknots.la
knotd_LDADD = libknotd.la libknot.la libknots.la @LIBOBJS@
knotc_LDADD = libknotd.la libknot.la libknots.la @LIBOBJS@
kdig_LDADD = libknotd.la libknot.la libknots.la @LIBOBJS@
khost_LDADD = libknotd.la libknot.la libknots.la @LIBOBJS@
knsupdate_LDADD = libknotd.la libknot.la libknots.la libzscanner.la @LIBOBJS@
knot_zcompile_LDADD = libknots.la libknot.la libknotd.la @LIBOBJS@
unittests_LDADD = libknotd.la libknots.la @LIBOBJS@
unittests_zcompile_LDADD = libknot.la libknots.la libknotd.la @LIBOBJS@
unittests_xfr_LDADD = libknotd.la libknot.la libknots.la @LIBOBJS@
unittests_zscanner_LDADD = libknots.la libknot.la libknotd.la libzscanner.la @LIBOBJS@

# automake complains on % rules:
#   `%'-style pattern rules are a GNU make extension

tests/sample_conf.rc: tests/files/sample_conf
	../resource.sh tests/files/sample_conf >$@

