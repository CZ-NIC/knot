ACLOCAL_AMFLAGS = -I ../m4
bin_PROGRAMS = knotc
libexec_PROGRAMS = knot-zcompile unittests unittests-zcompile
sbin_PROGRAMS = knotd

# $(YACC) will generate header file
AM_YFLAGS = -d
libknot_la_YFLAGS = -pcf_ -d
libknot_la_LFLAGS = # TODO: reentrant parser, prefix

LDADD = libknot.la @LIBOBJS@

BUILT_SOURCES =					\
	tests/dnslib/parsed_data.rc		\
	tests/dnslib/raw_data_queries.rc	\
	tests/dnslib/raw_data.rc		\
	tests/dnslib/parsed_data_queries.rc     \
        tests/sample_conf.rc

CLEANFILES =					\
	tests/dnslib/parsed_data.rc		\
	tests/dnslib/raw_data_queries.rc	\
	tests/dnslib/raw_data.rc		\
	tests/dnslib/parsed_data_queries.rc     \
        tests/sample_conf.rc                    \
	zparser.h				\
	zparser.c				\
	zlexer.c				\
        libknot_la-cf-lex.c			\
        libknot_la-cf-parse.c			\
        libknot_la-cf-parse.h

knotc_SOURCES =					\
	knot/ctl/knotc_main.c

knot_zcompile_SOURCES =			\
	zoneparser/zoneparser_main.c            \
	zoneparser/parser-util.h		\
	zoneparser/parser-descriptor.h		\
	zoneparser/zparser.y			\
	zoneparser/zlexer.l			\
	zoneparser/zoneparser.c			\
	zoneparser/parser-util.c		\
	zoneparser/parser-descriptor.c		

unittests_SOURCES =				\
	tests/libtap/tap.c			\
	tests/unittests_main.c

unittests_zcompile_SOURCES =		\
	zoneparser/parser-util.h		\
	zoneparser/parser-descriptor.h		\
	zoneparser/zparser.y			\
	zoneparser/zlexer.l			\
	zoneparser/zoneparser.c			\
	zoneparser/parser-util.c		\
	zoneparser/parser-descriptor.c		\
	tests/libtap/tap.c			\
	zoneparser/tests/unittests_zp_main.c	

nodist_unittests_SOURCES =			\
	tests/dnslib/parsed_data.rc		\
	tests/dnslib/raw_data_queries.rc	\
	tests/dnslib/raw_data.rc		\
	tests/dnslib/parsed_data_queries.rc     \
        tests/sample_conf.rc

knotd_SOURCES =					\
	knot/main.c

noinst_LTLIBRARIES = libknot.la
libknot_la_SOURCES =				\
	common/slab/slab.c				\
	common/slab/malloc.c				\
	common/slab/slab.h			        \
	common/slab/malloc.h				\
	common/lists.c	            		\
	common/base32.c				\
	common/lists.h	            		\
	common/base32.h				\
	common/print.c				\
	common/print.h				\
	common/dynamic-array.c			\
	common/skip-list.c				\
	common/base32hex.c				\
	common/skip-list.h				\
	common/dynamic-array.h			\
	common/tree.h				\
	common/base32hex.h				\
	knot/stat/gatherer.c				\
	knot/stat/stat.c				\
	knot/stat/gatherer.h				\
	knot/stat/stat.h				\
	dnslib/edns.c                           \
	dnslib/utils.c				\
	dnslib/rrset.c				\
	dnslib/dname.c				\
	dnslib/node.c				\
	dnslib/response.c			\
	dnslib/zone.c				\
	dnslib/zonedb.c				\
	dnslib/zone-load.c			\
	dnslib/debug.c				\
	dnslib/zone-dump.c			\
	dnslib/rdata.c				\
	dnslib/descriptor.c			\
	dnslib/nsec3.c				\
	dnslib/hash/hash-functions.c			\
	dnslib/hash/cuckoo-hash-table.c		\
	dnslib/hash/universal-system.c			\
	dnslib/hash/universal-system.h			\
	dnslib/hash/cuckoo-hash-table.h		\
	dnslib/hash/hash-functions.h			\
	dnslib/zonedb.h				\
	dnslib/consts.h				\
	dnslib/node.h				\
	dnslib/edns.h				\
	dnslib/zone.h				\
	dnslib/rdata.h				\
	dnslib/descriptor.h			\
	dnslib/dnslib.h				\
	dnslib/tolower.h			\
	dnslib/zone-dump.h			\
	dnslib/dname.h				\
	dnslib/response.h			\
	dnslib/rrset.h				\
	dnslib/zone-load.h			\
	dnslib/utils.h				\
	dnslib/packet.h				\
	dnslib/debug.h				\
	dnslib/nsec3.h				\
	knot/common.h				\
	knot/other/log.c				\
	knot/other/log.h				\
	knot/other/debug.h			\
	knot/conf/cf-parse.y                         \
	knot/conf/cf-lex.l                           \
	knot/conf/conf.c                             \
	knot/conf/logconf.c                          \
	knot/conf/logconf.h                          \
	knot/conf/conf.h                             \
	knot/ctl/process.c				\
	knot/ctl/process.h		                \
	knot/server/dthreads.c			\
	knot/server/socket.c				\
	knot/server/name-server.c			\
	knot/server/server.c				\
	knot/server/udp-handler.c			\
	knot/server/tcp-handler.c			\
	knot/server/socket.h				\
	knot/server/name-server.h			\
	knot/server/udp-handler.h			\
	knot/server/tcp-handler.h			\
	knot/server/dthreads.h			\
	knot/server/server.h				\
	tests/libtap/tap.h			\
	tests/tap_unit.h

libknot_la_LIBADD = @LIBOBJS@

# automake complains on % rules:
#   `%'-style pattern rules are a GNU make extension

tests/dnslib/parsed_data.rc: tests/files/parsed_data
	../resource.sh $< >$@

tests/dnslib/parsed_data_queries.rc: tests/files/parsed_data_queries
	../resource.sh $< >$@

tests/dnslib/raw_data_queries.rc: tests/files/raw_data_queries
	../resource.sh $< >$@

tests/dnslib/raw_data.rc: tests/files/raw_data
	../resource.sh $< >$@

tests/sample_conf.rc: tests/files/sample_conf
	../resource.sh $< >$@

