ACLOCAL_AMFLAGS = -I ../m4

libexec_PROGRAMS = knot-zcompile unittests unittests-zcompile unittests-libknot-realdata unittests-libknot unittests-xfr unittests-zscanner
sbin_PROGRAMS = knotc knotd
dist_man_MANS = knot.conf.5 knotc.8 knotd.8

# $(YACC) will generate header file
AM_CFLAGS = -Wall -Ilibknot -DLIBEXECDIR='"$(libexecdir)"' -DSYSCONFDIR='"$(sysconfdir)"' -DSBINDIR='"$(sbindir)"'
AM_YFLAGS = -d
libknotd_la_YFLAGS = -pcf_ -d
libknotd_la_LFLAGS = # TODO: reentrant parser, prefix

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

unittests_zscanner_SOURCES =			\
	zscanner/test/zscanner_test.c		\
	zscanner/test/tests.h			\
	zscanner/test/tests.c			\
	zscanner/test/processing.h		\
	zscanner/test/processing.c


noinst_LTLIBRARIES = libknot.la libknots.la libzscanner.la

libknot_la_SOURCES =				\
	libknot/util/utils.c			\
	libknot/util/debug.c			\
	libknot/util/debug.h			\
	libknot/util/utils.h			\
	libknot/util/tolower.h			\
	libknot/util/tolower.c			\
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
	libknot/rrset.c				\
	libknot/dname.c				\
	libknot/dname.h				\
	libknot/rrset.h				

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
	common/base32.c				\
	common/base64.c				\
	common/base64.h				\
	common/lists.h				\
	common/heap.h				\
	common/heap.c				\
	common/base32.h				\
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

zscanner/scanner.c: zscanner/scanner.rl zscanner/scanner_body.rl
	$(RAGEL) -s -o zscanner/scanner.c zscanner/scanner.rl

libzscanner_la_SOURCES =			\
	zscanner/file_loader.h			\
	zscanner/file_loader.c			\
	zscanner/scanner.h			\
	zscanner/scanner.c			\
	zscanner/scanner_functions.h		\
	zscanner/scanner_functions.c

libknots_la_LIBADD = @LIBOBJS@
knot_zcompile_LDADD = libknots.la libknot.la libknotd.la libzscanner.la @LIBOBJS@
unittests_zscanner_LDADD = libknots.la libknot.la libknotd.la libzscanner.la @LIBOBJS@

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

