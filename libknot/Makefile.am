ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -Wall

lib_LTLIBRARIES = libknot.la

libknot_common_SOURCES = \
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
	common/base32hex.h			\
	common/modified-tree.h			\
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
	common/errors.c

libknot_la_SOURCES =			\
	$(libknot_common_SOURCES)	\
	edns.c				\
	error.c				\
	utils.c				\
	rrset.c				\
	dname.c				\
	node.c				\
	packet.c			\
	query.c				\
	response2.c			\
	response.c			\
	zone.c				\
	zone-contents.c			\
	zonedb.c			\
	debug.c				\
	zone-tree.c			\
	zone-tree.h			\
	rdata.c				\
	descriptor.c			\
	nsec3.c				\
	dname-table.c			\
	hash/hash-functions.c		\
	hash/cuckoo-hash-table.c	\
	hash/universal-system.c		\
	hash/universal-system.h		\
	hash/cuckoo-hash-table.h	\
	hash/hash-functions.h		\
	zonedb.h			\
	consts.h			\
	node.h				\
	edns.h				\
	zone.h				\
	zone-contents.h			\
	rdata.h				\
	descriptor.h			\
	libknot.h			\
	tolower.h			\
	tolower.c			\
	dname.h				\
	packet.h			\
	query.h				\
	response2.h			\
	response.h			\
	rrset.h				\
	utils.h				\
	wire.h				\
	debug.h				\
	nsec3.h				\
	changesets.h			\
	changesets.c			\
	xfr-in.h			\
	xfr-in.c			\
	name-server.h			\
	name-server.c			\
	dname-table.h
