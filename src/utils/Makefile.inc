bin_PROGRAMS =
sbin_PROGRAMS =

if HAVE_LIBUTILS
noinst_LTLIBRARIES += libknotus.la

libknotus_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(gnutls_CFLAGS) \
                        $(libedit_CFLAGS) $(libidn2_CFLAGS) $(libidn_CFLAGS) \
                        $(libkqueue_CFLAGS) $(libnghttp2_CFLAGS) $(libngtcp2_CFLAGS) \
                        $(lmdb_CFLAGS)
libknotus_la_LDFLAGS  = $(AM_LDFLAGS) $(LDFLAG_EXCLUDE_LIBS)
libknotus_la_LIBADD   = $(libidn2_LIBS) $(libidn_LIBS) $(libnghttp2_LIBS) $(libngtcp2_LIBS)
libknotus_LIBS        = libknotus.la libknot.la libdnssec.la $(libcontrib_LIBS) \
                        $(gnutls_LIBS) $(libedit_LIBS)

if EMBEDDED_LIBNGTCP2
libknotus_la_LIBADD += $(libembngtcp2_LIBS)
endif EMBEDDED_LIBNGTCP2

libknotus_la_SOURCES = \
	utils/common/cert.c			\
	utils/common/cert.h			\
	utils/common/exec.c			\
	utils/common/exec.h			\
	utils/common/hex.c			\
	utils/common/hex.h			\
	utils/common/https.c			\
	utils/common/https.h			\
	utils/common/lookup.c			\
	utils/common/lookup.h			\
	utils/common/msg.c			\
	utils/common/msg.h			\
	utils/common/netio.c			\
	utils/common/netio.h			\
	utils/common/params.c			\
	utils/common/params.h			\
	utils/common/resolv.c			\
	utils/common/resolv.h			\
	utils/common/sign.c			\
	utils/common/sign.h			\
	utils/common/tls.c			\
	utils/common/tls.h			\
	utils/common/token.c			\
	utils/common/token.h			\
	utils/common/util_conf.c		\
	utils/common/util_conf.h
endif HAVE_LIBUTILS

if HAVE_UTILS
bin_PROGRAMS += kdig khost knsec3hash knsupdate

kdig_SOURCES = \
	utils/kdig/kdig_exec.c			\
	utils/kdig/kdig_exec.h			\
	utils/kdig/kdig_main.c			\
	utils/kdig/kdig_params.c		\
	utils/kdig/kdig_params.h

khost_SOURCES = \
	utils/kdig/kdig_exec.c			\
	utils/kdig/kdig_exec.h			\
	utils/kdig/kdig_params.c		\
	utils/kdig/kdig_params.h		\
	utils/khost/khost_main.c		\
	utils/khost/khost_params.c		\
	utils/khost/khost_params.h

knsec3hash_SOURCES = \
	utils/knsec3hash/knsec3hash.c

knsupdate_SOURCES = \
	utils/knsupdate/knsupdate_exec.c		\
	utils/knsupdate/knsupdate_exec.h		\
	utils/knsupdate/knsupdate_interactive.c		\
	utils/knsupdate/knsupdate_interactive.h		\
	utils/knsupdate/knsupdate_main.c		\
	utils/knsupdate/knsupdate_params.c		\
	utils/knsupdate/knsupdate_params.h

kdig_CPPFLAGS          = $(libknotus_la_CPPFLAGS)
kdig_LDADD             = $(libknotus_LIBS)
khost_CPPFLAGS         = $(libknotus_la_CPPFLAGS)
khost_LDADD            = $(libknotus_LIBS)
knsec3hash_CPPFLAGS    = $(libknotus_la_CPPFLAGS)
knsec3hash_LDADD       = libknot.la libdnssec.la $(libcontrib_LIBS)
knsupdate_CPPFLAGS     = $(libknotus_la_CPPFLAGS)
knsupdate_LDADD        = $(libknotus_LIBS) libzscanner.la

if HAVE_DNSTAP
kdig_CPPFLAGS          += $(DNSTAP_CFLAGS)
kdig_LDADD             += $(libdnstap_LIBS)
khost_CPPFLAGS         += $(DNSTAP_CFLAGS)
khost_LDADD            += $(libdnstap_LIBS)
endif HAVE_DNSTAP

if ENABLE_XDP
sbin_PROGRAMS += kxdpgun
kxdpgun_SOURCES = \
	utils/kxdpgun/ip_route.c		\
	utils/kxdpgun/ip_route.h		\
	utils/kxdpgun/load_queries.c		\
	utils/kxdpgun/load_queries.h		\
	utils/kxdpgun/main.c

kxdpgun_CPPFLAGS  = $(libknotus_la_CPPFLAGS) $(libmnl_CFLAGS)
kxdpgun_LDADD     = libknot.la $(libcontrib_LIBS) $(libmnl_LIBS) $(pthread_LIBS)
endif ENABLE_XDP
endif HAVE_UTILS

if HAVE_DAEMON
# Create storage and run-time directories
install-data-hook:
	$(INSTALL) -d $(DESTDIR)/@config_dir@
	$(INSTALL) -d $(DESTDIR)/@run_dir@
	$(INSTALL) -d $(DESTDIR)/@storage_dir@

sbin_PROGRAMS += knotc knotd

knotc_SOURCES = \
	utils/knotc/commands.c			\
	utils/knotc/commands.h			\
	utils/knotc/interactive.c		\
	utils/knotc/interactive.h		\
	utils/knotc/process.c			\
	utils/knotc/process.h			\
	utils/knotc/main.c

knotd_SOURCES = \
	utils/knotd/main.c

knotc_CPPFLAGS         = $(libknotus_la_CPPFLAGS)
knotc_LDADD            = $(libknotd_LIBS) $(libknotus_LIBS)
knotc_LDFLAGS          = $(AM_LDFLAGS) -rdynamic
knotd_CPPFLAGS         = $(libknotus_la_CPPFLAGS) $(liburcu_CFLAGS) $(systemd_CFLAGS)
knotd_LDADD            = $(malloc_LIBS) $(libknotd_LIBS) $(cap_ng_LIBS)
knotd_LDFLAGS          = $(AM_LDFLAGS) -rdynamic

if HAVE_UTILS
bin_PROGRAMS += kzonecheck kzonesign
sbin_PROGRAMS += keymgr kjournalprint kcatalogprint

kzonecheck_SOURCES = \
	utils/kzonecheck/main.c			\
	utils/kzonecheck/zone_check.c		\
	utils/kzonecheck/zone_check.h

kzonesign_SOURCES = \
	utils/kzonesign/main.c

keymgr_SOURCES = \
	utils/keymgr/bind_privkey.c		\
	utils/keymgr/bind_privkey.h		\
	utils/keymgr/functions.c		\
	utils/keymgr/functions.h		\
	utils/keymgr/offline_ksk.c		\
	utils/keymgr/offline_ksk.h		\
	utils/keymgr/main.c

kjournalprint_SOURCES = \
	utils/kjournalprint/main.c

kcatalogprint_SOURCES = \
	utils/kcatalogprint/main.c

kzonecheck_CPPFLAGS    = $(libknotus_la_CPPFLAGS)
kzonecheck_LDADD       = $(libknotd_LIBS)
kzonesign_CPPFLAGS     = $(libknotus_la_CPPFLAGS)
kzonesign_LDADD        = $(libknotd_LIBS) $(libknotus_LIBS)
keymgr_CPPFLAGS        = $(libknotus_la_CPPFLAGS)
keymgr_LDADD           = $(libknotd_LIBS) $(libknotus_LIBS)
kjournalprint_CPPFLAGS = $(libknotus_la_CPPFLAGS)
kjournalprint_LDADD    = $(libknotd_LIBS) $(libknotus_LIBS)
kcatalogprint_CPPFLAGS = $(libknotus_la_CPPFLAGS)
kcatalogprint_LDADD    = $(libknotd_LIBS) $(libknotus_LIBS)
endif HAVE_UTILS
endif HAVE_DAEMON
