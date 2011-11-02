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

libknot_la_SOURCES =				\
	$(libknot_common_SOURCES)		\
	util/error.c				\
	util/utils.c				\
	util/debug.c				\
	util/debug.h				\
	util/utils.h				\
	util/descriptor.c			\
	util/tolower.h				\
	util/tolower.c				\
	util/descriptor.h			\
	util/wire.h				\
	packet/query.c				\
	packet/response.c			\
	packet/packet.c				\
	packet/packet.h				\
	packet/query.h				\
	packet/response.h			\
	zone/zone.c				\
	zone/zone-contents.c			\
	zone/zone-tree.c			\
	zone/zone-tree.h			\
	zone/node.h				\
	zone/zone.h				\
	zone/zone-contents.h			\
	zone/zonedb.c				\
	zone/zonedb.h				\
	zone/node.c				\
	zone/dname-table.h			\
	zone/dname-table.c			\
	hash/hash-functions.c			\
	hash/cuckoo-hash-table.c		\
	hash/universal-system.c			\
	hash/universal-system.h			\
	hash/cuckoo-hash-table.h		\
	hash/hash-functions.h			\
	nameserver/name-server.h		\
	nameserver/name-server.c		\
	updates/changesets.h			\
	updates/changesets.c			\
	updates/xfr-in.h			\
	updates/xfr-in.c			\
	updates/ddns.h				\
	updates/ddns.c				\
	edns.c				\
	rrset.c				\
	dname.c				\
	rdata.c				\
	nsec3.c				\
	consts.h			\
	edns.h				\
	rdata.h				\
	libknot.h			\
	dname.h				\
	rrset.h				\
	nsec3.h				\
	tsig.h				\
	tsig.c				\
	tsig-op.h			\
	tsig-op.c
