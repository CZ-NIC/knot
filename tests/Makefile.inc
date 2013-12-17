# -*- mode: makefile; -*-
check_PROGRAMS = \
	tests/runtests \
	tests/journal \
	tests/slab \
	tests/hattrie \
	tests/hhash \
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
	tests/zonedb \
	tests/dnssec_keys \
	tests/dnssec_nsec3 \
	tests/dnssec_sign \
	tests/dnssec_zone_nsec \
	tests/rrset

check_LIBRARIES = tests/tap/libtap.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/tests

tests_runtests_CPPFLAGS = \
	-DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'

tests_tap_libtap_a_CPPFLAGS = -I$(abs_top_srcdir)/tests
tests_tap_libtap_a_SOURCES = \
	tests/tap/basic.c tests/tap/basic.h \
	tests/tap/float.c tests/tap/float.h \
	tests/tap/macros.h

check-compile-only: $(check_PROGRAMS)

check-local: $(check_PROGRAMS)
	cd tests && ./runtests -l $(abs_top_srcdir)/tests/TESTS

LDADD = \
	tests/tap/libtap.a \
	src/libknotd.la src/libknots.la \
	@LIBOBJS@

tests_conf_SOURCES = tests/conf.c tests/sample_conf.h
nodist_tests_conf_SOURCES = tests/sample_conf.c
CLEANFILES = tests/sample_conf.c

EXTRA_DIST = tests/data tests/TESTS

dist_check_SCRIPTS = tests/resource.sh

tests/sample_conf.c: tests/data/sample_conf
	$(abs_top_srcdir)/tests/resource.sh $(abs_top_srcdir)/tests/data/sample_conf >$@
