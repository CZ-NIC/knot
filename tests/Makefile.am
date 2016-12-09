AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(top_srcdir)/libtap \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/dnssec/lib

LDADD = \
	$(top_builddir)/libtap/libtap.la \
	$(top_builddir)/src/libknot.la \
	$(top_builddir)/src/libknotd.la \
	$(top_builddir)/src/libcontrib.la \
	$(libcrypto_LIBS)

check_PROGRAMS = \
	contrib/test_base32hex		\
	contrib/test_base64		\
	contrib/test_endian		\
	contrib/test_heap		\
	contrib/test_hhash		\
	contrib/test_net		\
	contrib/test_net_shortwrite	\
	contrib/test_qp-trie		\
	contrib/test_sockaddr		\
	contrib/test_string		\
	contrib/test_strtonum		\
	contrib/test_wire		\
	contrib/test_wire_ctx

check_PROGRAMS += \
	libknot/test_control		\
	libknot/test_cookies-client	\
	libknot/test_cookies-opt   	\
	libknot/test_cookies-server	\
	libknot/test_db			\
	libknot/test_descriptor		\
	libknot/test_dname		\
	libknot/test_edns		\
	libknot/test_edns_ecs		\
	libknot/test_lookup		\
	libknot/test_pkt		\
	libknot/test_rdata		\
	libknot/test_rdataset		\
	libknot/test_rrset		\
	libknot/test_rrset-wire		\
	libknot/test_tsig		\
	libknot/test_yparser		\
	libknot/test_ypscheme		\
	libknot/test_yptrafo

check_PROGRAMS += \
	modules/online_sign		\
	utils/test_cert			\
	utils/test_lookup		\
	acl				\
	changeset			\
	conf				\
	conf_tools			\
	confdb				\
	confio				\
	dthreads			\
	fdset				\
	journal				\
	node				\
	process_answer			\
	process_query			\
	query_module			\
	requestor			\
	rrl				\
	server				\
	worker_pool			\
	worker_queue			\
	zone_events			\
	zone_serial			\
	zone_timers			\
	zone_update			\
	zonedb				\
	ztree

utils_test_lookup_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(libedit_CFLAGS)

utils_test_lookup_LDADD = \
	$(top_builddir)/libtap/libtap.la \
	$(top_builddir)/src/libknotus.la \
	$(libedit_LIBS)

utils_test_cert_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(libedit_CFLAGS) \
	$(gnutls_CFLAGS)

utils_test_cert_LDADD = \
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
