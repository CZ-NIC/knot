ACLOCAL_AMFLAGS = -I ../m4

libexec_PROGRAMS = knot-zcompile unittests-libknot
sbin_PROGRAMS = 
dist_man_MANS = knot.conf.5 knotc.8 knotd.8

# $(YACC) will generate header file
AM_CFLAGS = -Wall -Ilibknot -DLIBEXECDIR='"$(libexecdir)"' -DSYSCONFDIR='"$(sysconfdir)"' -DSBINDIR='"$(sbindir)"'
AM_YFLAGS = -d
libknotd_la_YFLAGS = -pcf_ -d
libknotd_la_LFLAGS = # TODO: reentrant parser, prefix

zscanner/scanner.c: zscanner/scanner.rl zscanner/scanner_body.rl
	$(RAGEL) -s -o zscanner/scanner.c zscanner/scanner.rl

knot_zcompile_SOURCES =				\
	libknot/rrset.c				\
	libknot/rrset.h				\
	common/slab/slab.c			\
	zcompile/zcompile_main.c		\
	zcompile/zcompile-error.c		\
	zcompile/zcompile.c			\
	zscanner/test/processing.h		\
	zscanner/test/processing.c		\
	libknot/util/utils.c			\
	libknot/util/debug.c			\
	libknot/util/debug.h			\
	libknot/util/utils.h			\
	libknot/util/tolower.h			\
	libknot/util/tolower.c			\
	libknot/util/wire.h			\
	libknot/packet/packet.h			\
	libknot/packet/packet.c			\
	libknot/packet/query.h			\
	libknot/packet/query.c			\
	libknot/zone/zone.c			\
	libknot/zone/zone-contents.c		\
	libknot/zone/zone-tree.c		\
	libknot/zone/zone-tree.h		\
	libknot/zone/node.h			\
	libknot/zone/zone.h			\
	libknot/zone/zone-contents.h		\
	libknot/zone/node.c			\
	libknot/zone/dname-table.h		\
	libknot/zone/dname-table.c		\
	libknot/zone/zonedb.h			\
	libknot/zone/zonedb.c			\
	libknot/dname.c				\
	libknot/dname.h				\
	libknot/nsec3.h				\
	libknot/nsec3.c				\
	libknot/edns.h				\
	libknot/edns.c				\
	libknot/tsig.h				\
	libknot/tsig.c				\
	libknot/tsig-op.h			\
	libknot/tsig-op.c			\
	common/slab/slab.h			\
	common/libtap/tap.c			\
	common/libtap/tap.h			\
	common/libtap/tap_unit.h		\
	common/hattrie/ahtable.c		\
	common/hattrie/ahtable.h		\
	common/hattrie/hat-trie.c		\
	common/hattrie/hat-trie.h		\
	common/hattrie/murmurhash3.c		\
	common/hattrie/murmurhash3.h		\
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
	common/log.h				\
	zscanner/file_loader.h			\
	zscanner/file_loader.c			\
	zscanner/scanner.h			\
	zscanner/scanner.c			\
	zscanner/scanner_functions.h		\
	zscanner/scanner_functions.c
	
unittests_libknot_SOURCES =			\
	tests/libknot/libknot/rrset_tests.c	\
	tests/libknot/libknot/rrset_tests.h	\
	tests/libknot/unittests_libknot.c


knot_zcompile_LDADD = @LIBOBJS@

unittests_libknot_LDADD = knot-zcompile.la @LIBOBJS@

# automake complains on % rules:
#   `%'-style pattern rules are a GNU make extension

tests/sample_conf.rc: tests/files/sample_conf
	../resource.sh tests/files/sample_conf >$@

