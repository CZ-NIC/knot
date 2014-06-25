AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(top_srcdir)/libtap \
	-I$(top_srcdir)/src

LDADD = \
	$(top_builddir)/libtap/libtap.a \
	$(top_builddir)/src/libknotd.la \
	$(top_builddir)/src/libknots.la

check_PROGRAMS = \
	journal				\
	slab				\
	hattrie				\
	hhash				\
	dthreads			\
	acl				\
	fdset				\
	base64				\
	base32hex			\
	descriptor			\
	server				\
	conf				\
	rrl				\
	wire				\
	dname				\
	ztree				\
	zonedb				\
	dnssec_keys			\
	dnssec_nsec3			\
	dnssec_sign			\
	dnssec_zone_nsec		\
	rdata				\
	rdataset			\
	rrset				\
	node				\
	edns				\
	pkt				\
	process_query			\
	process_answer			\
	requestor			\
	query_module			\
	worker_pool			\
	worker_queue			\
	zone_events


check-compile-only: $(check_PROGRAMS)

check-local: $(check_PROGRAMS)
	$(top_builddir)/libtap/runtests -s $(top_srcdir)/tests \
					-b $(top_builddir)/tests \
					-L $(top_builddir)/tests/runtests.log \
					$(check_PROGRAMS)

EXTRA_DIST = data
dist_check_SCRIPTS = resource.sh

conf_SOURCES = conf.c sample_conf.h
process_query_SOURCES = process_query.c fake_server.h
process_answer_SOURCES = process_answer.c fake_server.h
nodist_conf_SOURCES = sample_conf.c
CLEANFILES = sample_conf.c runtests.log
sample_conf.c: data/sample_conf
	$(abs_srcdir)/resource.sh $(abs_srcdir)/data/sample_conf >$@
