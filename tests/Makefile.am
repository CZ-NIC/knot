AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h	\
	-I$(top_srcdir)/src			\
	-I$(top_srcdir)/src/libdnssec		\
	-I$(top_srcdir)/src/libdnssec/shared	\
	$(gnutls_CFLAGS)			\
	$(libkqueue_CFLAGS)			\
	$(lmdb_CFLAGS)

LDADD = \
	libtap.la

if HAVE_DAEMON
LDADD += \
	$(top_builddir)/src/libknotd.la		\
	$(liburcu_LIBS)				\
	$(systemd_LIBS)
endif HAVE_DAEMON

LDADD += \
	$(top_builddir)/src/libknot.la		\
	$(top_builddir)/src/libdnssec.la	\
	$(top_builddir)/src/libcontrib.la       \
	$(top_builddir)/src/libzscanner.la      \
	$(gnutls_LIBS)				\
	$(lmdb_LIBS)

EXTRA_DIST = \
	tap/libtap.sh				\
	libdnssec/sample_keys.h			\
	knot/semantic_check_data		\
	knot/test_semantic_check.in		\
	libzscanner/data			\
	libzscanner/test_zscanner.in		\
	libzscanner/TESTS

check_LTLIBRARIES = libtap.la

libtap_la_SOURCES = \
	tap/basic.c				\
	tap/basic.h				\
	tap/files.c				\
	tap/files.h				\
	tap/float.c				\
	tap/float.h				\
	tap/macros.h

EXTRA_PROGRAMS = tap/runtests

check_PROGRAMS = \
	contrib/test_base32hex			\
	contrib/test_base64			\
	contrib/test_base64url			\
	contrib/test_heap			\
	contrib/test_net			\
	contrib/test_net_shortwrite		\
	contrib/test_qp-trie			\
	contrib/test_qp-cow			\
	contrib/test_siphash			\
	contrib/test_sockaddr			\
	contrib/test_spinlock			\
	contrib/test_string			\
	contrib/test_strtonum			\
	contrib/test_time			\
	contrib/test_wire_ctx

check_PROGRAMS += \
	libdnssec/test_binary			\
	libdnssec/test_crypto			\
	libdnssec/test_key			\
	libdnssec/test_key_algorithm		\
	libdnssec/test_key_ds			\
	libdnssec/test_keyid			\
	libdnssec/test_keystore_pkcs11		\
	libdnssec/test_keystore_pkcs8		\
	libdnssec/test_keytag			\
	libdnssec/test_nsec_bitmap		\
	libdnssec/test_nsec_hash		\
	libdnssec/test_random			\
	libdnssec/test_sign			\
	libdnssec/test_sign_der			\
	libdnssec/test_shared_bignum		\
	libdnssec/test_shared_dname		\
	libdnssec/test_tsig

if HAVE_DAEMON
check_PROGRAMS += \
	knot/test_acl				\
	knot/test_changeset			\
	knot/test_conf				\
	knot/test_conf_tools			\
	knot/test_confdb			\
	knot/test_confio			\
	knot/test_digest			\
	knot/test_dthreads			\
	knot/test_fdset				\
	knot/test_journal			\
	knot/test_kasp_db			\
	knot/test_node				\
	knot/test_process_query			\
	knot/test_query_module			\
	knot/test_requestor			\
	knot/test_server			\
	knot/test_unreachable			\
	knot/test_worker_pool			\
	knot/test_worker_queue			\
	knot/test_zone-tree			\
	knot/test_zone-update			\
	knot/test_zone_events			\
	knot/test_zone_serial			\
	knot/test_zone_timers			\
	knot/test_zonedb

knot_test_acl_SOURCES = \
	knot/test_acl.c				\
	knot/test_conf.h

knot_test_conf_SOURCES = \
	knot/test_conf.c			\
	knot/test_conf.h

knot_test_confdb_SOURCES = \
	knot/test_confdb.c			\
	knot/test_conf.h

knot_test_confio_SOURCES = \
	knot/test_confio.c			\
	knot/test_conf.h

knot_test_process_query_SOURCES = \
	knot/test_process_query.c		\
	knot/test_server.h			\
	knot/test_conf.h
endif HAVE_DAEMON

check_PROGRAMS += \
	libknot/test_control			\
	libknot/test_cookies			\
	libknot/test_db				\
	libknot/test_descriptor			\
	libknot/test_dname			\
	libknot/test_dynarray			\
	libknot/test_edns			\
	libknot/test_edns_ecs			\
	libknot/test_endian			\
	libknot/test_lookup			\
	libknot/test_pkt			\
	libknot/test_probe			\
	libknot/test_rdata			\
	libknot/test_rdataset			\
	libknot/test_rrset			\
	libknot/test_rrset-wire			\
	libknot/test_tsig			\
	libknot/test_yparser			\
	libknot/test_ypschema			\
	libknot/test_yptrafo			\
	libknot/test_wire

if ENABLE_XDP
AM_CPPFLAGS += $(libbpf_CFLAGS)
check_PROGRAMS += \
	libknot/test_xdp_tcp
endif ENABLE_XDP

if HAVE_LIBUTILS
check_PROGRAMS += \
	utils/test_cert				\
	utils/test_lookup
endif HAVE_LIBUTILS

if HAVE_DAEMON
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
endif HAVE_DAEMON

libdnssec_test_keystore_pkcs11_CPPFLAGS = \
	$(AM_CPPFLAGS)				\
	-DLIBDIR='"$(libdir)"'

if HAVE_LIBUTILS
utils_test_lookup_CPPFLAGS = \
	$(AM_CPPFLAGS)				\
	$(libedit_CFLAGS)

utils_test_lookup_LDADD = \
	$(top_builddir)/src/libknotus.la	\
	$(libedit_LIBS)				\
	$(LDADD)

utils_test_cert_CPPFLAGS = \
	$(AM_CPPFLAGS)				\
	$(libedit_CFLAGS)

utils_test_cert_LDADD = \
	$(top_builddir)/src/libknotus.la	\
	$(libedit_LIBS)				\
	$(LDADD)
endif HAVE_LIBUTILS

EXTRA_PROGRAMS += libzscanner/zscanner-tool

libzscanner_zscanner_tool_SOURCES = \
	libzscanner/zscanner-tool.c		\
	libzscanner/processing.h		\
	libzscanner/processing.c

check_SCRIPTS = \
	libzscanner/test_zscanner

edit = $(SED) \
	-e 's|@top_srcdir[@]|$(abs_top_srcdir)|g' \
	-e 's|@top_builddir[@]|$(abs_top_builddir)|g'

if HAVE_LIBUTILS
check_SCRIPTS += \
	knot/test_semantic_check

knot/test_semantic_check:
	@$(edit) < $(top_srcdir)/tests/$@.in > $(top_builddir)/tests/$@
	@chmod +x $(top_builddir)/tests/$@
endif HAVE_LIBUTILS

libzscanner/test_zscanner: libzscanner/zscanner-tool
	@$(edit) < $(top_srcdir)/tests/$@.in > $(top_builddir)/tests/$@
	@chmod +x $(top_builddir)/tests/$@

CLEANFILES = $(check_SCRIPTS) $(EXTRA_PROGRAMS) runtests.log

check-compile: $(check_LTLIBRARIES) $(EXTRA_PROGRAMS) $(check_PROGRAMS) $(check_SCRIPTS)

AM_V_RUNTESTS = $(am__v_RUNTESTS_@AM_V@)
am__v_RUNTESTS_ = $(am__v_RUNTESTS_@AM_DEFAULT_V@)
am__v_RUNTESTS_0 =
am__v_RUNTESTS_1 = RET=$$?; if [ "$$RET" != "0" ]; then cat "$(builddir)/runtests.log"; exit $$RET; fi
check-local: $(check_LTLIBRARIES) $(EXTRA_PROGRAMS) $(check_PROGRAMS) $(check_SCRIPTS)
	@$(top_builddir)/tests/tap/runtests -s $(srcdir) -b $(builddir)  \
	 -L $(builddir)/runtests.log $(check_PROGRAMS) $(check_SCRIPTS); \
	$(AM_V_RUNTESTS)
