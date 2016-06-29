/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "knot/conf/scheme.h"
#include "knot/conf/tools.h"
#include "knot/common/log.h"
#include "knot/server/rrl.h"
#include "knot/updates/acl.h"
#include "libknot/rrtype/opt.h"
#include "dnssec/lib/dnssec/tsig.h"
#include "dnssec/lib/dnssec/key.h"

#include "knot/modules/synth_record.h"
#include "knot/modules/dnsproxy.h"
#include "knot/modules/online_sign/module.h"
#ifdef HAVE_ROSEDB
#include "knot/modules/rosedb.h"
#endif
#if USE_DNSTAP
#include "knot/modules/dnstap.h"
#endif

#define HOURS(x)	((x) * 3600)
#define DAYS(x)		((x) * HOURS(24))

static const knot_lookup_t keystore_backends[] = {
	{ KEYSTORE_BACKEND_PEM,    "pem" },
	{ KEYSTORE_BACKEND_PKCS11, "pkcs11" },
	{ 0, NULL }
};

static const knot_lookup_t tsig_key_algs[] = {
	{ DNSSEC_TSIG_HMAC_MD5,    "hmac-md5" },
	{ DNSSEC_TSIG_HMAC_SHA1,   "hmac-sha1" },
	{ DNSSEC_TSIG_HMAC_SHA224, "hmac-sha224" },
	{ DNSSEC_TSIG_HMAC_SHA256, "hmac-sha256" },
	{ DNSSEC_TSIG_HMAC_SHA384, "hmac-sha384" },
	{ DNSSEC_TSIG_HMAC_SHA512, "hmac-sha512" },
	{ 0, NULL }
};

static const knot_lookup_t dnssec_key_algs[] = {
	{ DNSSEC_KEY_ALGORITHM_DSA_SHA1,          "dsa" },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA1,          "rsasha1" },
	{ DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3,    "dsa-nsec3-sha1" },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3,    "rsasha1-nsec3-sha1" },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA256,        "rsasha256" },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA512,        "rsasha512" },
	{ DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256, "ecdsap256sha256" },
	{ DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384, "ecdsap384sha384" },
	{ 0, NULL }
};

const knot_lookup_t acl_actions[] = {
	{ ACL_ACTION_NOTIFY,   "notify" },
	{ ACL_ACTION_TRANSFER, "transfer" },
	{ ACL_ACTION_UPDATE,   "update" },
	{ 0, NULL }
};

static const knot_lookup_t serial_policies[] = {
	{ SERIAL_POLICY_INCREMENT, "increment" },
	{ SERIAL_POLICY_UNIXTIME,  "unixtime" },
	{ 0, NULL }
};

static const knot_lookup_t log_severities[] = {
	{ LOG_UPTO(LOG_CRIT),    "critical" },
	{ LOG_UPTO(LOG_ERR),     "error" },
	{ LOG_UPTO(LOG_WARNING), "warning" },
	{ LOG_UPTO(LOG_NOTICE),  "notice" },
	{ LOG_UPTO(LOG_INFO),    "info" },
	{ LOG_UPTO(LOG_DEBUG),   "debug" },
	{ 0, NULL }
};

static const yp_item_t desc_server[] = {
	{ C_IDENT,               YP_TSTR,  YP_VNONE },
	{ C_VERSION,             YP_TSTR,  YP_VNONE },
	{ C_NSID,                YP_THEX,  YP_VNONE },
	{ C_RUNDIR,              YP_TSTR,  YP_VSTR = { RUN_DIR } },
	{ C_USER,                YP_TSTR,  YP_VNONE },
	{ C_PIDFILE,             YP_TSTR,  YP_VSTR = { "knot.pid" } },
	{ C_UDP_WORKERS,         YP_TINT,  YP_VINT = { 1, 255, YP_NIL } },
	{ C_TCP_WORKERS,         YP_TINT,  YP_VINT = { 1, 255, YP_NIL } },
	{ C_BG_WORKERS,          YP_TINT,  YP_VINT = { 1, 255, YP_NIL } },
	{ C_ASYNC_START,         YP_TBOOL, YP_VNONE },
	{ C_TCP_HSHAKE_TIMEOUT,  YP_TINT,  YP_VINT = { 0, INT32_MAX, 5, YP_STIME } },
	{ C_TCP_IDLE_TIMEOUT,    YP_TINT,  YP_VINT = { 0, INT32_MAX, 20, YP_STIME } },
	{ C_TCP_REPLY_TIMEOUT,   YP_TINT,  YP_VINT = { 0, INT32_MAX, 10, YP_STIME } },
	{ C_MAX_TCP_CLIENTS,     YP_TINT,  YP_VINT = { 0, INT32_MAX, 100 } },
	{ C_MAX_UDP_PAYLOAD,     YP_TINT,  YP_VINT = { KNOT_EDNS_MIN_UDP_PAYLOAD,
	                                               KNOT_EDNS_MAX_UDP_PAYLOAD,
	                                               4096, YP_SSIZE } },
	{ C_RATE_LIMIT,          YP_TINT,  YP_VINT = { 0, INT32_MAX, 0 } },
	{ C_RATE_LIMIT_SLIP,     YP_TINT,  YP_VINT = { 0, RRL_SLIP_MAX, 1 } },
	{ C_RATE_LIMIT_TBL_SIZE, YP_TINT,  YP_VINT = { 1, INT32_MAX, 393241 } },
	{ C_RATE_LIMIT_WHITELIST,YP_TDATA, YP_VDATA = { 0, NULL, addr_range_to_bin,
	                                                addr_range_to_txt }, YP_FMULTI },
	{ C_LISTEN,              YP_TADDR, YP_VADDR = { 53 }, YP_FMULTI },
	{ C_COMMENT,             YP_TSTR,  YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_control[] = {
	{ C_LISTEN,  YP_TSTR, YP_VSTR = { "knot.sock" } },
	{ C_TIMEOUT, YP_TINT, YP_VINT = { 0, INT32_MAX, 5, YP_STIME } },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_log[] = {
	{ C_TARGET,  YP_TSTR, YP_VNONE },
	{ C_SERVER,  YP_TOPT, YP_VOPT = { log_severities, 0 } },
	{ C_ZONE,    YP_TOPT, YP_VOPT = { log_severities, 0 } },
	{ C_ANY,     YP_TOPT, YP_VOPT = { log_severities, 0 } },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_keystore[] = {
	{ C_ID,      YP_TSTR, YP_VNONE },
	{ C_BACKEND, YP_TOPT, YP_VOPT = { keystore_backends, KEYSTORE_BACKEND_PEM } },
	{ C_CONFIG,  YP_TSTR, YP_VSTR = { "keys" } },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_policy[] = {
	{ C_ID,             YP_TSTR,  YP_VNONE },
	{ C_KEYSTORE,       YP_TREF,  YP_VREF = { C_KEYSTORE }, YP_FNONE, { check_ref_dflt } },
	{ C_MANUAL,         YP_TBOOL, YP_VNONE },
	{ C_ALG,            YP_TOPT,  YP_VOPT = { dnssec_key_algs,
	                                          DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256 } },
	{ C_KSK_SIZE,       YP_TINT,  YP_VINT = { 0, UINT16_MAX, YP_NIL, YP_SSIZE } },
	{ C_ZSK_SIZE,       YP_TINT,  YP_VINT = { 0, UINT16_MAX, YP_NIL, YP_SSIZE } },
	{ C_DNSKEY_TTL,     YP_TINT,  YP_VINT = { 0, UINT32_MAX, YP_NIL, YP_STIME } },
	{ C_ZSK_LIFETIME,   YP_TINT,  YP_VINT = { 0, UINT32_MAX, DAYS(30), YP_STIME } },
	{ C_RRSIG_LIFETIME, YP_TINT,  YP_VINT = { 0, UINT32_MAX, DAYS(14), YP_STIME } },
	{ C_RRSIG_REFRESH,  YP_TINT,  YP_VINT = { 0, UINT32_MAX, DAYS(7), YP_STIME } },
	{ C_NSEC3,          YP_TBOOL, YP_VNONE },
	{ C_NSEC3_ITER,     YP_TINT,  YP_VINT = { 0, UINT16_MAX, 5 } },
	{ C_NSEC3_SALT_LEN, YP_TINT,  YP_VINT = { 0, UINT8_MAX, 8 } },
	{ C_NSEC3_RESALT,   YP_TINT,  YP_VINT = { 0, UINT32_MAX, DAYS(30), YP_STIME } },
	{ C_PROPAG_DELAY,   YP_TINT,  YP_VINT = { 0, UINT32_MAX, HOURS(1), YP_STIME } },
	{ C_COMMENT,        YP_TSTR,  YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_key[] = {
	{ C_ID,      YP_TDNAME, YP_VNONE },
	{ C_ALG,     YP_TOPT,   YP_VOPT = { tsig_key_algs, DNSSEC_TSIG_UNKNOWN } },
	{ C_SECRET,  YP_TB64,   YP_VNONE },
	{ C_COMMENT, YP_TSTR,   YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_acl[] = {
	{ C_ID,      YP_TSTR,  YP_VNONE },
	{ C_ADDR,    YP_TDATA, YP_VDATA = { 0, NULL, addr_range_to_bin,
	                                    addr_range_to_txt }, YP_FMULTI },
	{ C_KEY,     YP_TREF,  YP_VREF = { C_KEY }, YP_FMULTI, { check_ref } },
	{ C_ACTION,  YP_TOPT,  YP_VOPT = { acl_actions, ACL_ACTION_NONE }, YP_FMULTI },
	{ C_DENY,    YP_TBOOL, YP_VNONE },
	{ C_COMMENT, YP_TSTR,  YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_remote[] = {
	{ C_ID,      YP_TSTR,  YP_VNONE },
	{ C_ADDR,    YP_TADDR, YP_VADDR = { 53 }, YP_FMULTI },
	{ C_VIA,     YP_TADDR, YP_VNONE, YP_FMULTI },
	{ C_KEY,     YP_TREF,  YP_VREF = { C_KEY }, YP_FNONE, { check_ref } },
	{ C_COMMENT, YP_TSTR,  YP_VNONE },
	{ NULL }
};

#define ZONE_ITEMS \
	{ C_FILE,                YP_TSTR,  YP_VNONE }, \
	{ C_STORAGE,             YP_TSTR,  YP_VSTR = { STORAGE_DIR } }, \
	{ C_MASTER,              YP_TREF,  YP_VREF = { C_RMT }, YP_FMULTI, { check_ref } }, \
	{ C_DDNS_MASTER,         YP_TREF,  YP_VREF = { C_RMT }, YP_FNONE, { check_ref } }, \
	{ C_NOTIFY,              YP_TREF,  YP_VREF = { C_RMT }, YP_FMULTI, { check_ref } }, \
	{ C_ACL,                 YP_TREF,  YP_VREF = { C_ACL }, YP_FMULTI, { check_ref } }, \
	{ C_SEM_CHECKS,          YP_TBOOL, YP_VNONE }, \
	{ C_DISABLE_ANY,         YP_TBOOL, YP_VNONE }, \
	{ C_ZONEFILE_SYNC,       YP_TINT,  YP_VINT = { -1, INT32_MAX, 0, YP_STIME } }, \
	{ C_IXFR_DIFF,           YP_TBOOL, YP_VNONE }, \
	{ C_MAX_JOURNAL_SIZE,    YP_TINT,  YP_VINT = { 0, INT64_MAX, INT64_MAX, YP_SSIZE } }, \
	{ C_KASP_DB,             YP_TSTR,  YP_VSTR = { "keys" } }, \
	{ C_DNSSEC_SIGNING,      YP_TBOOL, YP_VNONE }, \
	{ C_DNSSEC_POLICY,       YP_TREF,  YP_VREF = { C_POLICY }, YP_FNONE, { check_ref_dflt } }, \
	{ C_SERIAL_POLICY,       YP_TOPT,  YP_VOPT = { serial_policies, SERIAL_POLICY_INCREMENT } }, \
	{ C_REQUEST_EDNS_OPTION, YP_TDATA, YP_VDATA = { 0, NULL, edns_opt_to_bin, edns_opt_to_txt } }, \
	{ C_MODULE,              YP_TDATA, YP_VDATA = { 0, NULL, mod_id_to_bin, mod_id_to_txt }, \
	                                   YP_FMULTI, { check_modref } }, \
	{ C_COMMENT,             YP_TSTR,  YP_VNONE },

static const yp_item_t desc_template[] = {
	{ C_ID, YP_TSTR, YP_VNONE },
	ZONE_ITEMS
	{ C_TIMER_DB,            YP_TSTR,  YP_VSTR = { "timers" } }, \
	{ C_GLOBAL_MODULE,       YP_TDATA, YP_VDATA = { 0, NULL, mod_id_to_bin, mod_id_to_txt }, \
	                                   YP_FMULTI, { check_modref } }, \
	{ NULL }
};

static const yp_item_t desc_zone[] = {
	{ C_DOMAIN, YP_TDNAME, YP_VNONE },
	{ C_TPL,    YP_TREF,   YP_VREF = { C_TPL }, YP_FNONE, { check_ref } },
	ZONE_ITEMS
	{ NULL }
};

const yp_item_t conf_scheme[] = {
	{ C_SRV,      YP_TGRP, YP_VGRP = { desc_server } },
	{ C_CTL,      YP_TGRP, YP_VGRP = { desc_control } },
	{ C_LOG,      YP_TGRP, YP_VGRP = { desc_log }, YP_FMULTI },
	{ C_KEYSTORE, YP_TGRP, YP_VGRP = { desc_keystore }, YP_FMULTI, { check_keystore } },
	{ C_POLICY,   YP_TGRP, YP_VGRP = { desc_policy }, YP_FMULTI, { check_policy } },
	{ C_KEY,      YP_TGRP, YP_VGRP = { desc_key }, YP_FMULTI, { check_key } },
	{ C_ACL,      YP_TGRP, YP_VGRP = { desc_acl }, YP_FMULTI, { check_acl } },
	{ C_RMT,      YP_TGRP, YP_VGRP = { desc_remote }, YP_FMULTI, { check_remote } },
/* MODULES */
	{ C_MOD_SYNTH_RECORD, YP_TGRP, YP_VGRP = { scheme_mod_synth_record }, YP_FMULTI,
	                                         { check_mod_synth_record } },
	{ C_MOD_DNSPROXY,     YP_TGRP, YP_VGRP = { scheme_mod_dnsproxy }, YP_FMULTI,
	                                         { check_mod_dnsproxy } },
#if HAVE_ROSEDB
	{ C_MOD_ROSEDB,       YP_TGRP, YP_VGRP = { scheme_mod_rosedb }, YP_FMULTI,
	                                         { check_mod_rosedb } },
#endif
#if USE_DNSTAP
	{ C_MOD_DNSTAP,       YP_TGRP, YP_VGRP = { scheme_mod_dnstap }, YP_FMULTI,
	                                         { check_mod_dnstap } },
#endif
	{ C_MOD_ONLINE_SIGN,  YP_TGRP, YP_VGRP = { scheme_mod_online_sign }, YP_FMULTI },
/***********/
	{ C_TPL,      YP_TGRP, YP_VGRP = { desc_template }, YP_FMULTI, { check_template } },
	{ C_ZONE,     YP_TGRP, YP_VGRP = { desc_zone }, YP_FMULTI, { check_zone } },
	{ C_INCL,     YP_TSTR, YP_VNONE, YP_FNONE, { include_file } },
	{ NULL }
};
