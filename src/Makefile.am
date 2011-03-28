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
	ctl/knotc_main.c

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
	main.c

noinst_LTLIBRARIES = libknot.la
libknot_la_SOURCES =				\
	common.h				\
	alloc/slab.c				\
	alloc/malloc.c				\
	conf/cf-parse.y                         \
	conf/cf-lex.l                           \
	conf/conf.c                             \
	conf/logconf.c                          \
	ctl/process.c				\
	lib/lists.c	            		\
        lib/evqueue.c                           \
	lib/dynamic-array.c			\
	lib/bitset.c				\
	lib/skip-list.c				\
	lib/base32.c				\
	lib/base32hex.c				\
	stat/gatherer.c				\
	stat/stat.c				\
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
	dnslib/tolower.c			\
	server/dthreads.c			\
	server/socket.c				\
	server/name-server.c			\
	server/server.c				\
	server/udp-handler.c			\
	server/tcp-handler.c			\
	hash/hash-functions.c			\
	hash/cuckoo-hash-table.c		\
	hash/universal-system.c			\
	other/log.c				\
	other/print.c				\
	alloc/slab.h			        \
	alloc/malloc.h				\
	conf/logconf.h                          \
	conf/conf.h                             \
	ctl/process.h		                \
	lib/lists.h	            		\
        lib/evqueue.h                           \
	lib/skip-list.h				\
	lib/dynamic-array.h			\
	lib/tree.h				\
	lib/bitset.h				\
	lib/base32.h				\
	lib/base32hex.h				\
	tests/libtap/tap.h			\
	tests/tap_unit.h			\
	stat/gatherer.h				\
	stat/stat.h				\
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
	server/socket.h				\
	server/name-server.h			\
	server/udp-handler.h			\
	server/tcp-handler.h			\
	server/dthreads.h			\
	server/server.h				\
	hash/universal-system.h			\
	hash/cuckoo-hash-table.h		\
	hash/hash-functions.h			\
	other/print.h				\
	other/log.h				\
	other/debug.h      

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

