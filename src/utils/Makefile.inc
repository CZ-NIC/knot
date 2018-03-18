noinst_LTLIBRARIES += libknotus.la

libknotus_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(libidn2_LIBS) \
                        $(libidn_CFLAGS) $(libedit_CFLAGS) $(gnutls_CFLAGS)
libknotus_la_LDFLAGS  = $(AM_LDFLAGS) $(LDFLAG_EXCLUDE_LIBS)
libknotus_la_LIBADD   = libcontrib.la libknot.la $(libidn2_LIBS) $(libidn_LIBS) \
                        $(libedit_LIBS) $(gnutls_LIBS)

libknotus_la_SOURCES = \
	utils/common/cert.c			\
	utils/common/cert.h			\
	utils/common/exec.c			\
	utils/common/exec.h			\
	utils/common/hex.c			\
	utils/common/hex.h			\
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
	utils/common/token.h

if HAVE_UTILS
bin_PROGRAMS = kdig khost knsec3hash knsupdate

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
	utils/knsupdate/knsupdate_exec.c	\
	utils/knsupdate/knsupdate_exec.h	\
	utils/knsupdate/knsupdate_main.c	\
	utils/knsupdate/knsupdate_params.c	\
	utils/knsupdate/knsupdate_params.h

kdig_CPPFLAGS          = $(AM_CPPFLAGS) $(gnutls_CFLAGS)
kdig_LDADD             = libknotus.la
khost_CPPFLAGS         = $(AM_CPPFLAGS) $(gnutls_CFLAGS)
khost_LDADD            = libknotus.la
knsec3hash_CPPFLAGS    = $(AM_CPPFLAGS)
knsec3hash_LDADD       = libcontrib.la libdnssec.la libknot.la libshared.la
knsupdate_CPPFLAGS     = $(AM_CPPFLAGS) $(gnutls_CFLAGS)
knsupdate_LDADD        = libknotus.la libzscanner.la

if HAVE_DNSTAP
kdig_LDADD             += $(DNSTAP_LIBS) libdnstap.la
khost_LDADD            += $(DNSTAP_LIBS) libdnstap.la
kdig_CPPFLAGS          += $(DNSTAP_CFLAGS)
khost_CPPFLAGS         += $(DNSTAP_CFLAGS)
endif HAVE_DNSTAP
endif HAVE_UTILS

if HAVE_DAEMON
# Create storage and run-time directories
install-data-hook:
	$(INSTALL) -d $(DESTDIR)/@config_dir@
	$(INSTALL) -d $(DESTDIR)/@run_dir@
	$(INSTALL) -d $(DESTDIR)/@storage_dir@

sbin_PROGRAMS = knotc knotd

knotc_SOURCES = \
	utils/knotc/commands.c			\
	utils/knotc/commands.h			\
	utils/knotc/estimator.c			\
	utils/knotc/estimator.h			\
	utils/knotc/interactive.c		\
	utils/knotc/interactive.h		\
	utils/knotc/process.c			\
	utils/knotc/process.h			\
	utils/knotc/main.c

knotd_SOURCES = \
	utils/knotd/main.c

knotc_CPPFLAGS         = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(libedit_CFLAGS)
knotc_LDADD            = libcontrib.la libknotd.la libknotus.la $(libedit_LIBS)
knotc_LDFLAGS          = $(AM_LDFLAGS) -rdynamic
knotd_CPPFLAGS         = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(liburcu_CFLAGS)
knotd_LDADD            = libcontrib.la libknotd.la $(liburcu_LIBS)
knotd_LDFLAGS          = $(AM_LDFLAGS) -rdynamic

if HAVE_UTILS
bin_PROGRAMS += kzonecheck
sbin_PROGRAMS += keymgr kjournalprint

kzonecheck_SOURCES = \
	utils/kzonecheck/main.c			\
	utils/kzonecheck/zone_check.c		\
	utils/kzonecheck/zone_check.h

keymgr_SOURCES = \
	utils/keymgr/bind_privkey.c		\
	utils/keymgr/bind_privkey.h		\
	utils/keymgr/functions.c		\
	utils/keymgr/functions.h		\
	utils/keymgr/main.c

kjournalprint_SOURCES = \
	utils/kjournalprint/main.c

kzonecheck_CPPFLAGS    = $(AM_CPPFLAGS)
kzonecheck_LDADD       = libcontrib.la libknotd.la
keymgr_CPPFLAGS        = $(AM_CPPFLAGS) $(gnutls_CFLAGS)
keymgr_LDADD           = libcontrib.la libknotd.la libknotus.la libdnssec.la \
                         libshared.la libzscanner.la
kjournalprint_CPPFLAGS = $(AM_CPPFLAGS) $(gnutls_CFLAGS)
kjournalprint_LDADD    = libcontrib.la libknotd.la
endif HAVE_UTILS
endif HAVE_DAEMON
