AM_CPPFLAGS = \
	-I$(top_srcdir)/libtap \
	-I$(top_srcdir)/src

LDADD = \
	$(top_srcdir)/libtap/libtap.a \
	$(top_srcdir)/src/libknotd.la \
	$(top_srcdir)/src/libknots.la

check_PROGRAMS = \
	journal			\
	slab			\
	hattrie			\
	hhash			\
	dthreads		\
	acl			\
	fdset			\
	base64			\
	base32hex		\
	descriptor		\
	server			\
	conf			\
	rrl			\
	wire			\
	dname			\
	ztree			\
	zonedb			\
	dnssec_keys		\
	dnssec_nsec3		\
	dnssec_sign		\
	dnssec_zone_nsec	\
	rrset			\
	pkt			\
	process_query

check-compile-only: $(check_PROGRAMS)

check-local: $(check_PROGRAMS)
	$(top_srcdir)/libtap/runtests \
		-s $(abs_top_srcdir)/tests -b $(abs_top_srcdir)/tests \
		$(check_PROGRAMS)

EXTRA_DIST = data
dist_check_SCRIPTS = resource.sh

conf_SOURCES = conf.c sample_conf.h
nodist_conf_SOURCES = sample_conf.c
CLEANFILES = sample_conf.c
sample_conf.c: data/sample_conf
	$(abs_srcdir)/resource.sh $(abs_srcdir)/data/sample_conf >$@
