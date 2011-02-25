ACLOCAL_AMFLAGS = -I../m4
bin_PROGRAMS = knotc
libexec_PROGRAMS = knot-zoneparser
sbin_PROGRAMS = knot

# FIXME: Move header files to $(topdir)/include
AM_CFLAGS =		\
	-I.		\
	-std=gnu99	\
	-D_XOPEN_SOURCE=600 \
	-D_GNU_SOURCE

# $(YACC) will generate header file
AM_YFLAGS = -d

LDADD = libknot.a @LIBOBJS@

TESTS = unittest

knotc_SOURCES =					\
	ctl/knotc_main.c

knot_zoneparser_SOURCES =			\
	zoneparser/zoneparser_main.c

#unittests_SOURCES =				\
#	tests/zonedb_tests.c			\
#	tests/dnslib_tests.c			\
#	tests/dthreads_tests.c			\
#	tests/libtap/tap.c			\
#	tests/da_tests.c			\
#	tests/server_tests.c			\
#	tests/slab_tests.c			\
#	tests/template_tests.c			\
#	tests/dnslib/dnslib_response_tests.c	\
#	tests/dnslib/dnslib_zone_tests.c	\
#	tests/dnslib/dnslib_rrsig_set_tests.c	\
#	tests/dnslib/dnslib_rrset_tests.c	\
#	tests/dnslib/dnslib_edns_tests.c	\
#	tests/dnslib/dnslib_rdata_tests.c	\
#	tests/dnslib/dnslib_node_tests.c	\
#	tests/dnslib/dnslib_dname_tests.c	\
#	tests/skiplist_tests.c			\
#	tests/cuckoo_tests.c			\
#	tests/unittests_main.c

knot_SOURCES =					\
	main.c

noinst_LIBRARIES = libknot.a
libknot_a_SOURCES =				\
	ctl/process.c				\
	zoneparser/zparser.y			\
	zoneparser/zlexer.l			\
	zoneparser/zoneparser.c			\
	zoneparser/parser-util.c		\
	zoneparser/parser-descriptor.c		\
	alloc/slab.c				\
	alloc/malloc.c				\
	lib/dynamic-array.c			\
	lib/bitset.c				\
	lib/skip-list.c				\
	stat/gatherer.c				\
	stat/stat.c				\
	dnslib/utils.c				\
	dnslib/rrset.c				\
	dnslib/dname.c				\
	dnslib/node.c				\
	dnslib/response.c			\
	dnslib/rrsig.c				\
	dnslib/zone.c				\
	dnslib/zonedb.c				\
	dnslib/zone-load.c			\
	dnslib/debug.c				\
	dnslib/zone-dump.c			\
	dnslib/rdata.c				\
	dnslib/descriptor.c			\
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
	src/alloc/slab.h			\
	alloc/malloc.h				\
	lib/skip-list.h				\
	lib/dynamic-array.h			\
	lib/tree.h				\
	lib/bitset.h				\
	common.h				\
	tests/libtap/tap.h			\
	tests/tap_unit.h			\
	zoneparser/parser-util.h		\
	zoneparser/parser-descriptor.h		\
	stat/gatherer.h				\
	stat/stat.h				\
	ctl/process.h				\
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
	dnslib/rrsig.h				\
	dnslib/response.h			\
	dnslib/rrset.h				\
	dnslib/zone-load.h			\
	dnslib/utils.h				\
	dnslib/packet.h				\
	dnslib/debug.h				\
	server/socket.h				\
	server/name-server.h			\
	server/udp-handler.h			\
	server/tcp-handler.h			\
	server/dthreads.h			\
	server/server.h				\
	hash/universal-system.h			\
	hash/cuckoo-hash-table.h		\
	hash/hash-functions.h			\
	config.h				\
	other/print.h				\
	other/log.h				\
	other/debug.h

libknot_a_LIBADD = @LIBOBJS@

