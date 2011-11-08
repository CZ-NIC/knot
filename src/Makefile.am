ACLOCAL_AMFLAGS = -I ../m4
libexec_PROGRAMS = knot-zcompile unittests unittests-zcompile unittests-libknot-realdata unittests-libknot
sbin_PROGRAMS = knotc knotd
MANPAGES = knotc.8 knotd.8
man8_MANS = knotc.8 knotd.8
EXTRA_DIST = $(man8_MANS)

# $(YACC) will generate header file
AM_CFLAGS = -Wall -Ilibknot -DLIBEXECDIR='"$(libexecdir)"' -DSYSCONFDIR='"$(sysconfdir)"' -DSBINDIR='"$(sbindir)"'
AM_YFLAGS = -d
libknotd_la_YFLAGS = -pcf_ -d
libknotd_la_LFLAGS = # TODO: reentrant parser, prefix

BUILT_SOURCES =					\
	tests/libknot/parsed_data.rc		\
	tests/libknot/realdata/parsed_data.rc	\
	tests/libknot/raw_data_queries.rc	\
	tests/libknot/raw_data.rc		\
	tests/libknot/realdata/raw_data.rc	\
	tests/libknot/parsed_data_queries.rc	\
	tests/sample_conf.rc			\
	zparser.h				\
	zparser.c				\
	zlexer.c				\
	libknotd_la-cf-lex.c			\
	libknotd_la-cf-parse.c			\
	libknotd_la-cf-parse.h

CLEANFILES =					\
	tests/libknot/parsed_data.rc		\
	tests/libknot/realdata/parsed_data.rc	\
	tests/libknot/raw_data_queries.rc	\
	tests/libknot/raw_data.rc		\
	tests/libknot/realdata/raw_data.rc	\
	tests/libknot/parsed_data_queries.rc	\
	tests/sample_conf.rc                    \
	zparser.h				\
	zparser.c				\
	zlexer.c				\
	libknotd_la-cf-lex.c			\
	libknotd_la-cf-parse.c			\
	libknotd_la-cf-parse.h

knotc_SOURCES =					\
	knot/ctl/knotc_main.c

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
	tests/common/da_tests.c			\
	tests/common/da_tests.h			\
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
	tests/unittests_main.c

unittests_libknot_realdata_SOURCES =			\
	tests/libknot/realdata/libknot/dname_tests_realdata.c	\
	tests/libknot/realdata/libknot/response_tests_realdata.c	\
	tests/libknot/realdata/libknot/edns_tests_realdata.c	\
	tests/libknot/realdata/libknot/node_tests_realdata.c	\
	tests/libknot/realdata/libknot/rdata_tests_realdata.c	\
	tests/libknot/realdata/libknot/rrset_tests_realdata.c	\
	tests/libknot/realdata/libknot/zone_tests_realdata.c	\
	tests/libknot/realdata/libknot/zonedb_tests_realdata.c	\
	tests/libknot/realdata/libknot/packet_tests_realdata.h	\
	tests/libknot/realdata/libknot/packet_tests_realdata.c	\
	tests/libknot/realdata/libknot_tests_loader_realdata.h	\
	tests/libknot/realdata/libknot_tests_loader_realdata.c	\
	tests/libknot/realdata/unittests_libknot_realdata.c

unittests_libknot_SOURCES =			\
	tests/libknot/libknot/cuckoo_tests.c	\
	tests/libknot/libknot/cuckoo_tests.h	\
	tests/libknot/libknot/response_tests.h	\
	tests/libknot/libknot/response_tests.c	\
	tests/libknot/libknot/dname_tests.c	\
	tests/libknot/libknot/dname_tests.h	\
	tests/libknot/libknot/dname_table_tests.h	\
	tests/libknot/libknot/dname_table_tests.c	\
	tests/libknot/libknot/nsec3_tests.h	\
	tests/libknot/libknot/nsec3_tests.c	\
	tests/libknot/libknot/packet_tests.h	\
	tests/libknot/libknot/packet_tests.c	\
	tests/libknot/libknot/query_tests.h	\
	tests/libknot/libknot/query_tests.c	\
	tests/libknot/libknot/edns_tests.c	\
	tests/libknot/libknot/edns_tests.h	\
	tests/libknot/libknot/node_tests.c	\
	tests/libknot/libknot/node_tests.h	\
	tests/libknot/libknot/rdata_tests.c	\
	tests/libknot/libknot/rdata_tests.h	\
	tests/libknot/libknot/rrset_tests.c	\
	tests/libknot/libknot/rrset_tests.h	\
	tests/libknot/libknot/zone_tests.c	\
	tests/libknot/libknot/zone_tests.h	\
	tests/libknot/libknot/zone_tree_tests.h\
	tests/libknot/libknot/zone_tree_tests.c	\
	tests/libknot/libknot/zonedb_tests.c	\
	tests/libknot/libknot/zonedb_tests.h	\
	tests/libknot/unittests_libknot.c

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

nodist_unittests_SOURCES =			\
	tests/libknot/parsed_data.rc		\
	tests/libknot/raw_data_queries.rc	\
	tests/libknot/raw_data.rc		\
	tests/libknot/parsed_data_queries.rc	\
	tests/sample_conf.rc

knotd_SOURCES =					\
	knot/main.c

noinst_LTLIBRARIES = libknot.la libknotd.la libknots.la

libknot_la_SOURCES =				\
	libknot/util/libknot_error.c		\
	libknot/util/utils.c			\
	libknot/util/debug.c			\
	libknot/util/debug.h			\
	libknot/util/utils.h			\
	libknot/util/descriptor.c		\
	libknot/util/tolower.h			\
	libknot/util/tolower.c			\
	libknot/util/descriptor.h		\
	libknot/util/wire.h			\
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
	common/slab/malloc.c			\
	common/slab/slab.h			\
	common/slab/malloc.h			\
	common/libtap/tap.c			\
	common/libtap/tap.h			\
	common/libtap/tap_unit.h		\
	common/lists.c				\
	common/base32.c				\
	common/lists.h				\
	common/base32.h				\
	common/print.c				\
	common/print.h				\
	common/dynamic-array.c			\
	common/skip-list.c			\
	common/base32hex.c			\
	common/skip-list.h			\
	common/general-tree.h			\
	common/general-tree.c			\
	common/dynamic-array.h			\
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
	common/crc.c				\
	common/ref.h				\
	common/ref.c				\
	common/errors.h				\
	common/errors.c				\
        common/WELL1024a.h			\
        common/WELL1024a.c			\
        common/fdset.h				\
        common/fdset.c				\
        common/fdset_poll.h			\
        common/fdset_poll.c			\
        common/fdset_kqueue.h			\
        common/fdset_kqueue.c			\
        common/fdset_epoll.h			\
        common/fdset_epoll.c			

libknotd_la_SOURCES =				\
	knot/stat/gatherer.c				\
	knot/stat/stat.c				\
	knot/stat/gatherer.h				\
	knot/stat/stat.h				\
	knot/common.h				\
	knot/other/log.c			\
	knot/other/log.h			\
	knot/other/debug.h			\
	knot/other/error.h			\
	knot/other/error.c			\
	knot/conf/cf-parse.y			\
	knot/conf/cf-lex.l			\
	knot/conf/conf.c			\
	knot/conf/logconf.c			\
	knot/conf/logconf.h			\
	knot/conf/conf.h			\
	knot/ctl/process.c			\
	knot/ctl/process.h			\
	knot/server/dthreads.c			\
	knot/server/journal.c			\
	knot/server/socket.c				\
	knot/server/server.c				\
	knot/server/udp-handler.c			\
	knot/server/tcp-handler.c			\
	knot/server/xfr-handler.c			\
	knot/server/zones.c				\
	knot/server/socket.h				\
	knot/server/udp-handler.h			\
	knot/server/tcp-handler.h			\
	knot/server/xfr-handler.h			\
	knot/server/dthreads.h			\
	knot/server/journal.h			\
	knot/server/zones.h				\
	knot/server/notify.h				\
	knot/server/notify.c				\
	knot/server/zones.h				\
	knot/zone/zone-load.c			\
	knot/zone/zone-load.h			\
	knot/zone/zone-dump.c			\
	knot/zone/zone-dump-text.c			\
	knot/zone/zone-dump-text.h			\
	knot/zone/zone-dump.h			\
	knot/server/server.h

libknotd_la_LIBADD = libknot.la libknots.la @LIBOBJS@
libknots_la_LIBADD = @LIBOBJS@
knotd_LDADD = libknotd.la libknot.la libknots.la @LIBOBJS@
knotc_LDADD = libknotd.la libknot.la libknots.la @LIBOBJS@
knot_zcompile_LDADD = libknots.la libknot.la libknotd.la @LIBOBJS@
unittests_LDADD = libknotd.la libknots.la @LIBOBJS@
unittests_zcompile_LDADD = libknot.la libknots.la libknotd.la @LIBOBJS@
unittests_libknot_LDADD = libknot.la libknots.la @LIBOBJS@
unittests_libknot_realdata_LDADD = libknot.la libknots.la @LIBOBJS@

# automake complains on % rules:
#   `%'-style pattern rules are a GNU make extension

tests/libknot/parsed_data.rc: tests/libknot/files/parsed_data
	../resource.sh tests/libknot/files/parsed_data >$@

tests/libknot/realdata/parsed_data.rc: tests/libknot/realdata/files/parsed_data
	../resource.sh tests/libknot/realdata/files/parsed_data >$@

tests/libknot/parsed_data_queries.rc: tests/libknot/files/parsed_data_queries
	../resource.sh tests/libknot/files/parsed_data_queries >$@

tests/libknot/raw_data_queries.rc: tests/libknot/files/raw_data_queries
	../resource.sh tests/libknot/files/raw_data_queries >$@

tests/libknot/raw_data.rc: tests/libknot/files/raw_data
	../resource.sh tests/libknot/files/raw_data >$@

tests/libknot/realdata/raw_data.rc: tests/libknot/realdata/files/raw_data
	../resource.sh tests/libknot/realdata/files/raw_data >$@

tests/sample_conf.rc: tests/files/sample_conf
	../resource.sh tests/files/sample_conf >$@

