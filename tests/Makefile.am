AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(top_srcdir)/libtap \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/dnssec/lib

LDADD = \
	$(top_builddir)/libtap/libtap.la \
	$(top_builddir)/src/libknot.la \
	$(top_builddir)/src/libknotd.la \
	$(libcrypto_LIBS)

check_PROGRAMS = \
	acl				\
	base32hex			\
	base64				\
	changeset			\
	conf				\
	conf_tools			\
	confdb				\
	confio				\
	control				\
	db				\
	descriptor			\
	dname				\
	dthreads			\
	edns				\
	endian				\
	fdset				\
	hattrie				\
	heap				\
	hhash				\
	internal_mem			\
	journal				\
	lookup				\
	net				\
	net_shortwrite			\
	node				\
	pkt				\
	process_answer			\
	process_query			\
	query_module			\
	rdata				\
	rdataset			\
	requestor			\
	rrl				\
	rrset				\
	rrset_wire			\
	server				\
	sockaddr			\
	tsig_key			\
	wire				\
	wire_ctx			\
	worker_pool			\
	worker_queue			\
	yparser				\
	ypscheme			\
	yptrafo				\
	zone_events			\
	zone_serial			\
	zone_timers			\
	zone_update			\
	zonedb				\
	ztree

check_PROGRAMS += \
	modules/online_sign		\
	utils/test_lookup

utils_test_lookup_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(libedit_CFLAGS)

utils_test_lookup_LDADD = \
	$(top_builddir)/libtap/libtap.la \
	$(top_builddir)/src/libknotus.la \
	$(libedit_LIBS)

CLEANFILES = runtests.log

include $(srcdir)/semantic_check_data/Makefile.inc

check-compile: $(check_PROGRAMS) $(check_SCRIPTS)

check-local: $(check_PROGRAMS) $(check_SCRIPTS)
	$(top_builddir)/libtap/runtests -s $(top_srcdir)/tests \
					-b $(top_builddir)/tests \
					-L $(top_builddir)/tests/runtests.log \
					$(check_PROGRAMS) $(check_SCRIPTS)

acl_SOURCES = acl.c test_conf.h
conf_SOURCES = conf.c test_conf.h
confdb_SOURCES = confdb.c test_conf.h
confio_SOURCES = confio.c test_conf.h
process_query_SOURCES = process_query.c fake_server.h test_conf.h
process_answer_SOURCES = process_answer.c fake_server.h test_conf.h
