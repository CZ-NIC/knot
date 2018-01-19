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
	contrib/test_dynarray		\
	contrib/test_heap		\
	contrib/test_net		\
	contrib/test_net_shortwrite	\
	contrib/test_qp-trie		\
	contrib/test_siphash		\
	contrib/test_sockaddr		\
	contrib/test_string		\
	contrib/test_strtonum		\
	contrib/test_time		\
	contrib/test_wire		\
	contrib/test_wire_ctx

check_PROGRAMS += \
	libknot/test_control		\
	libknot/test_cookies		\
	libknot/test_db			\
	libknot/test_descriptor		\
	libknot/test_dname		\
	libknot/test_edns		\
	libknot/test_edns_ecs		\
	libknot/test_endian		\
	libknot/test_lookup		\
	libknot/test_pkt		\
	libknot/test_rdata		\
	libknot/test_rdataset		\
	libknot/test_rrset		\
	libknot/test_rrset-wire		\
	libknot/test_tsig		\
	libknot/test_yparser		\
	libknot/test_ypschema		\
	libknot/test_yptrafo

check_PROGRAMS += \
	utils/test_cert			\
	utils/test_lookup

check_PROGRAMS += \
	test_acl			\
	test_changeset			\
	test_conf			\
	test_conf_tools			\
	test_confdb			\
	test_confio			\
	test_dthreads			\
	test_fdset			\
	test_journal			\
	test_kasp_db			\
	test_node			\
	test_process_query		\
	test_query_module		\
	test_requestor			\
	test_server			\
	test_worker_pool		\
	test_worker_queue		\
	test_zone-tree			\
	test_zone-update		\
	test_zone_events		\
	test_zone_serial		\
	test_zone_timers		\
	test_zonedb

if STATIC_MODULE_onlinesign
check_PROGRAMS += \
	modules/test_onlinesign
else
if SHARED_MODULE_onlinesign
check_PROGRAMS += \
	modules/test_onlinesign
endif
endif

if STATIC_MODULE_rrl
check_PROGRAMS += \
	modules/test_rrl
else
if SHARED_MODULE_rrl
check_PROGRAMS += \
	modules/test_rrl
endif
endif

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

AM_V_RUNTESTS = $(am__v_RUNTESTS_@AM_V@)
am__v_RUNTESTS_ = $(am__v_RUNTESTS_@AM_DEFAULT_V@)
am__v_RUNTESTS_0 =
am__v_RUNTESTS_1 = RET=$$?; if [ "$$RET" != "0" ]; then cat "$(builddir)/runtests.log"; exit $$RET; fi
check-local: $(check_PROGRAMS) $(check_SCRIPTS)
	$(top_builddir)/libtap/runtests -s $(srcdir) \
					-b $(builddir) \
					-L $(builddir)/runtests.log \
					$(check_PROGRAMS) $(check_SCRIPTS); \
	$(AM_V_RUNTESTS)

test_acl_SOURCES = test_acl.c test_conf.h
test_conf_SOURCES = test_conf.c test_conf.h
test_confdb_SOURCES = test_confdb.c test_conf.h
test_confio_SOURCES = test_confio.c test_conf.h
test_process_query_SOURCES = test_process_query.c test_server.h test_conf.h
