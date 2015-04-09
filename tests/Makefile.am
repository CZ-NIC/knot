AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(top_srcdir)/libtap \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/dnssec/lib

AM_LDFLAGS = \
	$(libcrypto_LIBS)

LDADD = \
	$(top_builddir)/libtap/libtap.a \
	$(top_builddir)/src/libknot-int.la \
	$(top_builddir)/src/libknotd.la \
	$(top_builddir)/src/libknot-yparser.la

check_PROGRAMS = \
	acl				\
	base32hex			\
	base64				\
	changeset			\
	descriptor			\
	dname				\
	dthreads			\
	edns				\
	endian				\
	fdset				\
	hattrie				\
	hhash				\
	journal				\
	namedb				\
	net_shortwrite			\
	node				\
	overlay				\
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
	utils				\
	wire				\
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

check-compile-only: $(check_PROGRAMS)

check-local: $(check_PROGRAMS)
	$(top_builddir)/libtap/runtests -s $(top_srcdir)/tests \
					-b $(top_builddir)/tests \
					-L $(top_builddir)/tests/runtests.log \
					$(check_PROGRAMS)

process_query_SOURCES = process_query.c fake_server.h
process_answer_SOURCES = process_answer.c fake_server.h
CLEANFILES = runtests.log
