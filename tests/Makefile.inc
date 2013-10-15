# -*- mode: makefile; -*-
check_PROGRAMS = \
	tests/runtests \
	tests/journal \
	tests/slab \
	tests/hattrie \
	tests/dthreads \
	tests/events \
	tests/acl \
	tests/fdset \
	tests/base64 \
	tests/base32hex \
	tests/descriptor \
	tests/server \
	tests/conf \
	tests/rrl \
	tests/wire \
	tests/dname \
	tests/ztree \
	tests/dnssec_keys \
	tests/dnssec_nsec3 \
	tests/dnssec_sign \
	tests/dnssec_zone_nsec \
	tests/rrset

check_LIBRARIES = tests/tap/libtap.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-DSBINDIR='"$(sbindir)"'

tests_runtests_CPPFLAGS = \
	-DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'

tests_tap_libtap_a_CPPFLAGS = -I$(abs_top_srcdir)/t
tests_tap_libtap_a_SOURCES = \
	tests/tap/basic.c tests/tap/basic.h \
	tests/tap/float.c tests/tap/float.h \
	tests/tap/macros.h

check-local: $(check_PROGRAMS)
	cd tests && ./runtests -l $(abs_top_srcdir)/tests/TESTS

LDADD = \
	tests/tap/libtap.a \
	src/libknotd.la src/libknots.la \
	@LIBOBJS@

EXTRA_DIST += \
	tests/data/sample_conf

BUILT_SOURCES = \
	tests/sample_conf.rc

CLEANFILES = \
	tests/sample_conf.rc

tests_conf_SOURCES = \
	tests/conf.c

nodist_tests_conf_SOURCES = \
	tests/sample_conf.rc

tests/sample_conf.rc: tests/data/sample_conf
	$(top_srcdir)/resource.sh $< >$@
