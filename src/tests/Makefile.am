ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

AM_CPPFLAGS = -I$(top_srcdir)/src/libknot -I$(top_srcdir)/src -DSYSCONFDIR='"$(sysconfdir)"' -DSBINDIR='"$(sbindir)"'

check_PROGRAMS = 			\
	unittests

TESTS = unittests

EXTRA_DIST =				\
	files/sample_conf

BUILT_SOURCES =				\
	sample_conf.rc

CLEANFILES =				\
	sample_conf.rc

nodist_unittests_SOURCES =		\
	sample_conf.rc

unittests_SOURCES =			\
	common/acl_tests.c		\
	common/acl_tests.h		\
	common/base32hex_tests.c	\
	common/base32hex_tests.h	\
	common/base64_tests.c		\
	common/base64_tests.h		\
	common/descriptor_tests.h	\
	common/descriptor_tests.c	\
	common/events_tests.c		\
	common/events_tests.h		\
	common/fdset_tests.c		\
	common/fdset_tests.h		\
	common/hattrie_tests.c		\
	common/hattrie_tests.h		\
	common/slab_tests.c		\
	common/slab_tests.h		\
	knot/conf_tests.c		\
	knot/conf_tests.h		\
	knot/dthreads_tests.c		\
	knot/dthreads_tests.h		\
	knot/journal_tests.c		\
	knot/journal_tests.h		\
	knot/server_tests.c		\
	knot/server_tests.h		\
	knot/rrl_tests.h		\
	knot/rrl_tests.c		\
	zscanner/zscanner_tests.h	\
	zscanner/zscanner_tests.c	\
	libknot/dname_tests.h		\
	libknot/dname_tests.c		\
	libknot/ztree_tests.h		\
	libknot/ztree_tests.c		\
	libknot/wire_tests.h		\
	libknot/wire_tests.c		\
	libknot/rrset_tests.c		\
	libknot/rrset_tests.h		\
	libknot/sign_tests.c		\
	libknot/sign_tests.h		\
	unittests_main.c

unittests_LDADD = ../libknotd.la ../libknots.la @LIBOBJS@

sample_conf.rc: files/sample_conf
	$(top_srcdir)/resource.sh $(srcdir)/files/sample_conf >$@
