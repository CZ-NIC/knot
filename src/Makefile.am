ACLOCAL_AMFLAGS = -I ../m4
bin_PROGRAMS = knotc
libexec_PROGRAMS = knot-zcompile unittests unittests-zcompile unittests-dnslib-realdata unittests-dnslib
sbin_PROGRAMS = knotd

# $(YACC) will generate header file
AM_CFLAGS = -Wall
AM_YFLAGS = -d
libknot_la_YFLAGS = -pcf_ -d
libknot_la_LFLAGS = # TODO: reentrant parser, prefix

LDADD = libknot.la @LIBOBJS@

BUILT_SOURCES =					\
	dnslib/tests/parsed_data.rc		\
	dnslib/tests/raw_data_queries.rc	\
	dnslib/tests/raw_data.rc		\
	dnslib/tests/parsed_data_queries.rc     \
	tests/sample_conf.rc

CLEANFILES =					\
	dnslib/tests/parsed_data.rc		\
	dnslib/tests/raw_data_queries.rc	\
	dnslib/tests/raw_data.rc		\
	dnslib/tests/parsed_data_queries.rc     \
	tests/sample_conf.rc                    \
	zparser.h				\
	zparser.c				\
	zlexer.c				\
	libknot_la-cf-lex.c			\
	libknot_la-cf-parse.c			\
	libknot_la-cf-parse.h

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
	tests/knot/conf_tests.c			\
	tests/knot/conf_tests.h			\
	tests/knot/dthreads_tests.c		\
	tests/knot/dthreads_tests.h		\
	tests/knot/journal_tests.c		\
	tests/knot/journal_tests.h		\
	tests/knot/server_tests.c		\
	tests/knot/server_tests.h		\
	tests/unittests_main.c

unittests_dnslib_realdata_SOURCES =			\
	dnslib/tests/realdata/dnslib/dname_tests_realdata.c	\
	dnslib/tests/realdata/dnslib/edns_tests_realdata.c	\
	dnslib/tests/realdata/dnslib/node_tests_realdata.c	\
	dnslib/tests/realdata/dnslib/rdata_tests_realdata.c	\
	dnslib/tests/realdata/dnslib/response_tests_realdata.c	\
	dnslib/tests/realdata/dnslib/rrset_tests_realdata.c	\
	dnslib/tests/realdata/dnslib/zone_tests_realdata.c	\
	dnslib/tests/realdata/dnslib/zonedb_tests_realdata.c	\
	dnslib/tests/realdata/dnslib_tests_loader_realdata.h	\
	dnslib/tests/realdata/dnslib_tests_loader_realdata.c	\
	dnslib/tests/realdata/unittests_dnslib_realdata.c

unittests_dnslib_SOURCES =			\
	dnslib/tests/dnslib/cuckoo_tests.c	\
	dnslib/tests/dnslib/cuckoo_tests.h	\
	dnslib/tests/dnslib/dname_tests.c	\
	dnslib/tests/dnslib/dname_tests.h	\
	dnslib/tests/dnslib/edns_tests.c	\
	dnslib/tests/dnslib/edns_tests.h	\
	dnslib/tests/dnslib/node_tests.c	\
	dnslib/tests/dnslib/node_tests.h	\
	dnslib/tests/dnslib/rdata_tests.c	\
	dnslib/tests/dnslib/rdata_tests.h	\
	dnslib/tests/dnslib/rrset_tests.c	\
	dnslib/tests/dnslib/rrset_tests.h	\
	dnslib/tests/dnslib/zone_tests.c	\
	dnslib/tests/dnslib/zone_tests.h	\
	dnslib/tests/dnslib/zonedb_tests.c	\
	dnslib/tests/dnslib/zonedb_tests.h	\
	dnslib/tests/unittests_dnslib.c

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
	dnslib/tests/parsed_data.rc		\
	dnslib/tests/raw_data_queries.rc	\
	dnslib/tests/raw_data.rc		\
	dnslib/tests/parsed_data_queries.rc     \
	tests/sample_conf.rc

knotd_SOURCES =					\
	knot/main.c

noinst_LTLIBRARIES = libknot.la
libknot_la_SOURCES =				\
	common/slab/slab.c			\
	common/slab/malloc.c			\
	common/slab/slab.h			\
	common/slab/malloc.h			\
	common/libtap/tap.c			\
	common/libtap/tap.h			\
	common/tap_unit.h			\
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
	common/base32hex.h				\
	common/evqueue.h		\
	common/evqueue.c		\
	common/evsched.h		\
	common/evsched.c		\
	common/acl.h				\
	common/acl.c				\
	common/sockaddr.h				\
	common/sockaddr.c				\
	common/crc.h				\
	common/crc.c				\
	knot/stat/gatherer.c				\
	knot/stat/stat.c				\
	knot/stat/gatherer.h				\
	knot/stat/stat.h				\
	dnslib/edns.c                           \
	common/errors.h				\
	common/errors.c				\
	dnslib/dnslib-error.c			\
	dnslib/utils.c				\
	dnslib/rrset.c				\
	dnslib/dname.c				\
	dnslib/node.c				\
	dnslib/packet.c			\
	dnslib/query.c			\
	dnslib/response2.c			\
	dnslib/response.c			\
	dnslib/zone.c				\
	dnslib/zone-contents.c			\
	dnslib/zonedb.c				\
	dnslib/zone-load.c			\
	dnslib/debug.c				\
	dnslib/zone-dump.c			\
	dnslib/zone-dump-text.c			\
	dnslib/zone-tree.c			\
	dnslib/zone-tree.h			\
	dnslib/rdata.c				\
	dnslib/descriptor.c			\
	dnslib/nsec3.c				\
	dnslib/dname-table.c			\
	dnslib/hash/hash-functions.c		\
	dnslib/hash/cuckoo-hash-table.c		\
	dnslib/hash/universal-system.c		\
	dnslib/hash/universal-system.h		\
	dnslib/hash/cuckoo-hash-table.h		\
	dnslib/hash/hash-functions.h		\
	dnslib/zonedb.h				\
	dnslib/consts.h				\
	dnslib/node.h				\
	dnslib/edns.h				\
	dnslib/zone.h				\
	dnslib/zone-contents.h			\
	dnslib/rdata.h				\
	dnslib/descriptor.h			\
	dnslib/dnslib.h				\
	dnslib/tolower.h			\
	dnslib/tolower.c			\
	dnslib/zone-dump.h			\
	dnslib/dname.h				\
	dnslib/packet.h			\
	dnslib/query.h				\
	dnslib/response2.h			\
	dnslib/response.h			\
	dnslib/rrset.h				\
	dnslib/zone-load.h			\
	dnslib/utils.h				\
	dnslib/wire.h				\
	dnslib/debug.h				\
	dnslib/nsec3.h				\
	dnslib/dname-table.h			\
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
	knot/server/name-server.c			\
	knot/server/server.c				\
	knot/server/udp-handler.c			\
	knot/server/tcp-handler.c			\
	knot/server/xfr-handler.c			\
	knot/server/zones.c				\
	knot/server/socket.h				\
	knot/server/name-server.h			\
	knot/server/udp-handler.h			\
	knot/server/tcp-handler.h			\
	knot/server/xfr-handler.h			\
	knot/server/dthreads.h			\
	knot/server/journal.h			\
	knot/server/zones.h				\
	knot/server/notify.h				\
	knot/server/notify.c				\
	knot/server/zones.h				\
	knot/server/xfr-in.h				\
	knot/server/xfr-in.c				\
	knot/server/server.h

libknot_la_LIBADD = @LIBOBJS@

# automake complains on % rules:
#   `%'-style pattern rules are a GNU make extension

dnslib/tests/parsed_data.rc: dnslib/tests/files/parsed_data
	../resource.sh dnslib/tests/files/parsed_data >$@

dnslib/tests/parsed_data_queries.rc: dnslib/tests/files/parsed_data_queries
	../resource.sh dnslib/tests/files/parsed_data_queries >$@

dnslib/tests/raw_data_queries.rc: dnslib/tests/files/raw_data_queries
	../resource.sh dnslib/tests/files/raw_data_queries >$@

dnslib/tests/raw_data.rc: dnslib/tests/files/raw_data
	../resource.sh dnslib/tests/files/raw_data >$@

tests/sample_conf.rc: tests/files/sample_conf
	../resource.sh tests/files/sample_conf >$@

