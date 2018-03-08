AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h \
	-I$(top_srcdir)/libtap \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/dnssec/lib \
	-I$(top_srcdir)/src/dnssec/shared \
	-I$(top_srcdir)/src/dnssec/lib/dnssec \
	$(gnutls_CFLAGS)

LDADD = \
	$(top_builddir)/libtap/libtap.la \
	$(top_builddir)/src/dnssec/libdnssec.la \
	$(top_builddir)/src/libknot.la \
	$(top_builddir)/src/libknotd.la \
	$(top_builddir)/src/libcontrib.la

EXTRA_DIST = dnssec/sample_keys.h

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
	contrib/test_wire_ctx

check_PROGRAMS += \
	dnssec/test_binary		\
	dnssec/test_crypto		\
	dnssec/test_key			\
	dnssec/test_key_algorithm	\
	dnssec/test_key_ds		\
	dnssec/test_keyid		\
	dnssec/test_keystore_pkcs11	\
	dnssec/test_keystore_pkcs8	\
	dnssec/test_keystore_pkcs8_dir	\
	dnssec/test_keytag		\
	dnssec/test_list		\
	dnssec/test_nsec_bitmap		\
	dnssec/test_nsec_hash		\
	dnssec/test_random		\
	dnssec/test_sign		\
	dnssec/test_sign_der		\
	dnssec/test_shared_bignum	\
	dnssec/test_shared_dname	\
	dnssec/test_tsig

check_PROGRAMS += \
	knot/test_acl			\
	knot/test_changeset		\
	knot/test_conf			\
	knot/test_conf_tools		\
	knot/test_confdb		\
	knot/test_confio		\
	knot/test_dthreads		\
	knot/test_fdset			\
	knot/test_journal		\
	knot/test_kasp_db		\
	knot/test_node			\
	knot/test_process_query		\
	knot/test_query_module		\
	knot/test_requestor		\
	knot/test_server		\
	knot/test_worker_pool		\
	knot/test_worker_queue		\
	knot/test_zone-tree		\
	knot/test_zone-update		\
	knot/test_zone_events		\
	knot/test_zone_serial		\
	knot/test_zone_timers		\
	knot/test_zonedb

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
	libknot/test_yptrafo		\
	libknot/test_wire		

check_PROGRAMS += \
	utils/test_cert			\
	utils/test_lookup

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

dnssec_keystore_pkcs11_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DLIBDIR='"$(libdir)"'

utils_test_lookup_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(libedit_CFLAGS)

utils_test_lookup_LDADD = \
	$(top_builddir)/libtap/libtap.la \
	$(top_builddir)/src/libknotus.la \
	$(libedit_LIBS)

utils_test_cert_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(libedit_CFLAGS)

utils_test_cert_LDADD = \
	$(top_builddir)/libtap/libtap.la \
	$(top_builddir)/src/libknotus.la \
	$(libedit_LIBS)

CLEANFILES = runtests.log

include $(srcdir)/knot/semantic_check_data/Makefile.inc

check-compile: $(check_PROGRAMS) $(check_SCRIPTS)

AM_V_RUNTESTS = $(am__v_RUNTESTS_@AM_V@)
am__v_RUNTESTS_ = $(am__v_RUNTESTS_@AM_DEFAULT_V@)
am__v_RUNTESTS_0 =
am__v_RUNTESTS_1 = RET=$$?; if [ "$$RET" != "0" ]; then cat "$(builddir)/runtests.log"; exit $$RET; fi
check-local: $(check_PROGRAMS) $(check_SCRIPTS)
	@$(top_builddir)/libtap/runtests -s $(srcdir) \
					-b $(builddir) \
					-L $(builddir)/runtests.log \
					$(check_PROGRAMS) $(check_SCRIPTS); \
	$(AM_V_RUNTESTS)

knot_test_acl_SOURCES = knot/test_acl.c knot/test_conf.h
knot_test_conf_SOURCES = knot/test_conf.c knot/test_conf.h
knot_test_confdb_SOURCES = knot/test_confdb.c knot/test_conf.h
knot_test_confio_SOURCES = knot/test_confio.c knot/test_conf.h
knot_test_process_query_SOURCES = knot/test_process_query.c knot/test_server.h knot/test_conf.h
