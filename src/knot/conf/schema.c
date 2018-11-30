/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "knot/conf/schema.h"
#include "knot/conf/confio.h"
#include "knot/conf/tools.h"
#include "knot/common/log.h"
#include "knot/journal/journal.h"
#include "knot/updates/acl.h"
#include "libknot/rrtype/opt.h"
#include "libdnssec/tsig.h"
#include "libdnssec/key.h"

#define HOURS(x)	((x) * 3600)
#define DAYS(x)		((x) * HOURS(24))

#define KILO(x)		(1024LLU * (x))
#define MEGA(x)		(KILO(1024) * (x))
#define GIGA(x)		(MEGA(1024) * (x))
#define TERA(x)		(GIGA(1024) * (x))

#define VIRT_MEM_TOP_32BIT	GIGA(1)
#define VIRT_MEM_LIMIT(x)	(((sizeof(void *) < 8) && ((x) > VIRT_MEM_TOP_32BIT)) \
				 ? VIRT_MEM_TOP_32BIT : (x))

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
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA1,          "rsasha1" },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3,    "rsasha1-nsec3-sha1" },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA256,        "rsasha256" },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA512,        "rsasha512" },
	{ DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256, "ecdsap256sha256" },
	{ DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384, "ecdsap384sha384" },
	{ DNSSEC_KEY_ALGORITHM_ED25519,           "ed25519" },
	/* Obsolete items. */
	{ 3, "dsa" },
	{ 6, "dsa-nsec3-sha1" },
	{ 0, NULL }
};

const knot_lookup_t child_record[] = {
	{ CHILD_RECORDS_NONE,     "none" },
	{ CHILD_RECORDS_EMPTY,    "delete-dnssec" },
	{ CHILD_RECORDS_ROLLOVER, "rollover" },
	{ CHILD_RECORDS_ALWAYS,   "always" },
	{ 0, NULL }
};

const knot_lookup_t acl_actions[] = {
	{ ACL_ACTION_NOTIFY,   "notify" },
	{ ACL_ACTION_TRANSFER, "transfer" },
	{ ACL_ACTION_UPDATE,   "update" },
	{ 0, NULL }
};

const knot_lookup_t acl_update_owner[] = {
	{ ACL_UPDATE_OWNER_KEY,  "key" },
	{ ACL_UPDATE_OWNER_ZONE, "zone" },
	{ ACL_UPDATE_OWNER_NAME, "name" },
	{ 0, NULL }
};

const knot_lookup_t acl_update_owner_match[] = {
	{ ACL_UPDATE_MATCH_SUBEQ, "sub-or-equal" },
	{ ACL_UPDATE_MATCH_EQ,    "equal" },
	{ ACL_UPDATE_MATCH_SUB,   "sub" },
	{ 0, NULL }
};

static const knot_lookup_t serial_policies[] = {
	{ SERIAL_POLICY_INCREMENT,  "increment" },
	{ SERIAL_POLICY_UNIXTIME,   "unixtime" },
	{ SERIAL_POLICY_DATESERIAL, "dateserial" },
	{ 0, NULL }
};

static const knot_lookup_t journal_content[] = {
	{ JOURNAL_CONTENT_NONE,    "none" },
	{ JOURNAL_CONTENT_CHANGES, "changes" },
	{ JOURNAL_CONTENT_ALL,     "all" },
	{ 0, NULL }
};

static const knot_lookup_t zonefile_load[] = {
	{ ZONEFILE_LOAD_NONE,  "none" },
	{ ZONEFILE_LOAD_DIFF,  "difference" },
	{ ZONEFILE_LOAD_DIFSE, "difference-no-serial" },
	{ ZONEFILE_LOAD_WHOLE, "whole" },
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

static const knot_lookup_t journal_modes[] = {
	{ JOURNAL_MODE_ROBUST, "robust" },
	{ JOURNAL_MODE_ASYNC,  "asynchronous" },
	{ 0, NULL }
};

static const yp_item_t desc_module[] = {
	{ C_ID,      YP_TSTR, YP_VNONE, YP_FNONE, { check_module_id } },
	{ C_FILE,    YP_TSTR, YP_VNONE },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_server[] = {
	{ C_IDENT,                YP_TSTR,  YP_VNONE },
	{ C_VERSION,              YP_TSTR,  YP_VNONE },
	{ C_NSID,                 YP_THEX,  YP_VNONE },
	{ C_RUNDIR,               YP_TSTR,  YP_VSTR = { RUN_DIR } },
	{ C_USER,                 YP_TSTR,  YP_VNONE },
	{ C_PIDFILE,              YP_TSTR,  YP_VSTR = { "knot.pid" } },
	{ C_UDP_WORKERS,          YP_TINT,  YP_VINT = { 1, 255, YP_NIL } },
	{ C_TCP_WORKERS,          YP_TINT,  YP_VINT = { 1, 255, YP_NIL } },
	{ C_BG_WORKERS,           YP_TINT,  YP_VINT = { 1, 255, YP_NIL } },
	{ C_ASYNC_START,          YP_TBOOL, YP_VNONE },
	{ C_TCP_HSHAKE_TIMEOUT,   YP_TINT,  YP_VINT = { 0, INT32_MAX, 5, YP_STIME } },
	{ C_TCP_IDLE_TIMEOUT,     YP_TINT,  YP_VINT = { 0, INT32_MAX, 20, YP_STIME } },
	{ C_TCP_REPLY_TIMEOUT,    YP_TINT,  YP_VINT = { 0, INT32_MAX, 10, YP_STIME } },
	{ C_MAX_TCP_CLIENTS,      YP_TINT,  YP_VINT = { 0, INT32_MAX, 100 } },
	{ C_MAX_UDP_PAYLOAD,      YP_TINT,  YP_VINT = { KNOT_EDNS_MIN_DNSSEC_PAYLOAD,
	                                                KNOT_EDNS_MAX_UDP_PAYLOAD,
	                                                KNOT_EDNS_MAX_UDP_PAYLOAD, YP_SSIZE } },
	{ C_MAX_IPV4_UDP_PAYLOAD, YP_TINT,  YP_VINT = { KNOT_EDNS_MIN_DNSSEC_PAYLOAD,
	                                                KNOT_EDNS_MAX_UDP_PAYLOAD,
	                                                KNOT_EDNS_MAX_UDP_PAYLOAD, YP_SSIZE } },
	{ C_MAX_IPV6_UDP_PAYLOAD, YP_TINT,  YP_VINT = { KNOT_EDNS_MIN_DNSSEC_PAYLOAD,
	                                                KNOT_EDNS_MAX_UDP_PAYLOAD,
	                                                KNOT_EDNS_MAX_UDP_PAYLOAD, YP_SSIZE } },
	{ C_LISTEN,               YP_TADDR, YP_VADDR = { 53 }, YP_FMULTI },
	{ C_ECS,                  YP_TBOOL, YP_VNONE },
	{ C_ANS_ROTATION,         YP_TBOOL, YP_VNONE },
	{ C_COMMENT,              YP_TSTR,  YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_control[] = {
	{ C_LISTEN,  YP_TSTR, YP_VSTR = { "knot.sock" } },
	{ C_TIMEOUT, YP_TINT, YP_VINT = { 0, INT32_MAX / 1000, 5, YP_STIME } },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_log[] = {
	{ C_TARGET,  YP_TSTR, YP_VNONE },
	{ C_SERVER,  YP_TOPT, YP_VOPT = { log_severities, 0 } },
	{ C_CTL,     YP_TOPT, YP_VOPT = { log_severities, 0 } },
	{ C_ZONE,    YP_TOPT, YP_VOPT = { log_severities, 0 } },
	{ C_ANY,     YP_TOPT, YP_VOPT = { log_severities, 0 } },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_stats[] = {
	{ C_TIMER,  YP_TINT,  YP_VINT = { 1, UINT32_MAX, 0, YP_STIME } },
	{ C_FILE,   YP_TSTR,  YP_VSTR = { "stats.yaml" } },
	{ C_APPEND, YP_TBOOL, YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_keystore[] = {
	{ C_ID,      YP_TSTR, YP_VNONE },
	{ C_BACKEND, YP_TOPT, YP_VOPT = { keystore_backends, KEYSTORE_BACKEND_PEM },
	                      CONF_IO_FRLD_ZONES },
	{ C_CONFIG,  YP_TSTR, YP_VSTR = { "keys" }, CONF_IO_FRLD_ZONES },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
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
	{ C_ID,                 YP_TSTR,   YP_VNONE, CONF_IO_FREF },
	{ C_ADDR,               YP_TNET,   YP_VNONE, YP_FMULTI },
	{ C_KEY,                YP_TREF,   YP_VREF = { C_KEY }, YP_FMULTI, { check_ref } },
	{ C_ACTION,             YP_TOPT,   YP_VOPT = { acl_actions, ACL_ACTION_NONE }, YP_FMULTI },
	{ C_DENY,               YP_TBOOL,  YP_VNONE },
	{ C_UPDATE_OWNER,       YP_TOPT,   YP_VOPT = { acl_update_owner, ACL_UPDATE_OWNER_NONE } },
	{ C_UPDATE_OWNER_MATCH, YP_TOPT,   YP_VOPT = { acl_update_owner_match, ACL_UPDATE_MATCH_SUBEQ } },
	{ C_UPDATE_OWNER_NAME,  YP_TDNAME, YP_VNONE, YP_FMULTI },
	{ C_UPDATE_TYPE,        YP_TDATA,  YP_VDATA = { 0, NULL, rrtype_to_bin, rrtype_to_txt },
	                                   YP_FMULTI, },
	{ C_COMMENT,            YP_TSTR,   YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_remote[] = {
	{ C_ID,      YP_TSTR,  YP_VNONE, CONF_IO_FREF },
	{ C_ADDR,    YP_TADDR, YP_VADDR = { 53 }, YP_FMULTI },
	{ C_VIA,     YP_TADDR, YP_VNONE, YP_FMULTI },
	{ C_KEY,     YP_TREF,  YP_VREF = { C_KEY }, YP_FNONE, { check_ref } },
	{ C_COMMENT, YP_TSTR,  YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_submission[] = {
	{ C_ID,           YP_TSTR, YP_VNONE },
	{ C_PARENT,       YP_TREF, YP_VREF = { C_RMT }, YP_FMULTI | CONF_IO_FRLD_ZONES,
	                           { check_ref } },
	{ C_CHK_INTERVAL, YP_TINT, YP_VINT = { 1, UINT32_MAX, HOURS(1), YP_STIME },
	                           CONF_IO_FRLD_ZONES },
	{ C_TIMEOUT,      YP_TINT, YP_VINT = { 1, UINT32_MAX, 0, YP_STIME },
	                           CONF_IO_FRLD_ZONES },
	{ NULL }
};

static const yp_item_t desc_policy[] = {
	{ C_ID,                  YP_TSTR,  YP_VNONE, CONF_IO_FREF },
	{ C_KEYSTORE,            YP_TREF,  YP_VREF = { C_KEYSTORE }, CONF_IO_FRLD_ZONES,
	                                   { check_ref_dflt } },
	{ C_MANUAL,              YP_TBOOL, YP_VNONE, CONF_IO_FRLD_ZONES },
	{ C_KSK_SHARED,          YP_TBOOL, YP_VNONE, CONF_IO_FRLD_ZONES },
	{ C_SINGLE_TYPE_SIGNING, YP_TBOOL, YP_VNONE, CONF_IO_FRLD_ZONES },
	{ C_ALG,                 YP_TOPT,  YP_VOPT = { dnssec_key_algs,
	                                               DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256 },
	                                   CONF_IO_FRLD_ZONES },
	{ C_KSK_SIZE,            YP_TINT,  YP_VINT = { 0, UINT16_MAX, YP_NIL, YP_SSIZE },
	                                   CONF_IO_FRLD_ZONES },
	{ C_ZSK_SIZE,            YP_TINT,  YP_VINT = { 0, UINT16_MAX, YP_NIL, YP_SSIZE },
	                                   CONF_IO_FRLD_ZONES },
	{ C_DNSKEY_TTL,          YP_TINT,  YP_VINT = { 0, UINT32_MAX, YP_NIL, YP_STIME },
	                                   CONF_IO_FRLD_ZONES },
	{ C_ZONE_MAX_TLL,        YP_TINT,  YP_VINT = { 0, UINT32_MAX, YP_NIL, YP_STIME },
	                                   CONF_IO_FRLD_ZONES },
	{ C_ZSK_LIFETIME,        YP_TINT,  YP_VINT = { 0, UINT32_MAX, DAYS(30), YP_STIME },
	                                   CONF_IO_FRLD_ZONES },
	{ C_KSK_LIFETIME,        YP_TINT,  YP_VINT = { 0, UINT32_MAX, 0, YP_STIME },
	                                   CONF_IO_FRLD_ZONES },
	{ C_PROPAG_DELAY,        YP_TINT,  YP_VINT = { 0, UINT32_MAX, HOURS(1), YP_STIME },
	                                   CONF_IO_FRLD_ZONES },
	{ C_RRSIG_LIFETIME,      YP_TINT,  YP_VINT = { 1, UINT32_MAX, DAYS(14), YP_STIME },
	                                   CONF_IO_FRLD_ZONES },
	{ C_RRSIG_REFRESH,       YP_TINT,  YP_VINT = { 1, UINT32_MAX, DAYS(7), YP_STIME },
	                                   CONF_IO_FRLD_ZONES },
	{ C_NSEC3,               YP_TBOOL, YP_VNONE, CONF_IO_FRLD_ZONES },
	{ C_NSEC3_ITER,          YP_TINT,  YP_VINT = { 0, UINT16_MAX, 10 }, CONF_IO_FRLD_ZONES },
	{ C_NSEC3_OPT_OUT,       YP_TBOOL, YP_VNONE, CONF_IO_FRLD_ZONES },
	{ C_NSEC3_SALT_LEN,      YP_TINT,  YP_VINT = { 0, UINT8_MAX, 8 }, CONF_IO_FRLD_ZONES },
	{ C_NSEC3_SALT_LIFETIME, YP_TINT,  YP_VINT = { 1, UINT32_MAX, DAYS(30), YP_STIME },
	                                   CONF_IO_FRLD_ZONES },
	{ C_KSK_SBM,             YP_TREF,  YP_VREF = { C_SBM }, CONF_IO_FRLD_ZONES,
	                                   { check_ref } },
	{ C_PARALLEL_SIGN,       YP_TINT,  YP_VINT = { 1, UINT16_MAX, 1, YP_SSIZE }, CONF_IO_FRLD_ZONES },
	{ C_CHILD_RECORDS,       YP_TOPT,  YP_VOPT = { child_record, CHILD_RECORDS_ALWAYS } },
	{ C_OFFLINE_KSK,         YP_TBOOL, YP_VNONE, CONF_IO_FRLD_ZONES },
	{ C_COMMENT,             YP_TSTR,  YP_VNONE },
	{ NULL }
};

#define ZONE_ITEMS(FLAGS) \
	{ C_STORAGE,             YP_TSTR,  YP_VSTR = { STORAGE_DIR }, FLAGS }, \
	{ C_FILE,                YP_TSTR,  YP_VNONE, FLAGS }, \
	{ C_MASTER,              YP_TREF,  YP_VREF = { C_RMT }, YP_FMULTI, { check_ref } }, \
	{ C_DDNS_MASTER,         YP_TREF,  YP_VREF = { C_RMT }, YP_FNONE, { check_ref } }, \
	{ C_NOTIFY,              YP_TREF,  YP_VREF = { C_RMT }, YP_FMULTI, { check_ref } }, \
	{ C_ACL,                 YP_TREF,  YP_VREF = { C_ACL }, YP_FMULTI, { check_ref } }, \
	{ C_SEM_CHECKS,          YP_TBOOL, YP_VNONE, FLAGS }, \
	{ C_DISABLE_ANY,         YP_TBOOL, YP_VNONE }, \
	{ C_ZONEFILE_SYNC,       YP_TINT,  YP_VINT = { -1, INT32_MAX, 0, YP_STIME } }, \
	{ C_JOURNAL_CONTENT,     YP_TOPT,  YP_VOPT = { journal_content, JOURNAL_CONTENT_CHANGES } }, \
	{ C_ZONEFILE_LOAD,       YP_TOPT,  YP_VOPT = { zonefile_load, ZONEFILE_LOAD_WHOLE } }, \
	{ C_MAX_ZONE_SIZE,       YP_TINT,  YP_VINT = { 0, SSIZE_MAX, SSIZE_MAX, YP_SSIZE }, FLAGS }, \
	{ C_MAX_JOURNAL_USAGE,   YP_TINT,  YP_VINT = { KILO(40), SSIZE_MAX, MEGA(100), YP_SSIZE } }, \
	{ C_MAX_JOURNAL_DEPTH,   YP_TINT,  YP_VINT = { 2, SSIZE_MAX, SSIZE_MAX } }, \
	{ C_DNSSEC_SIGNING,      YP_TBOOL, YP_VNONE, FLAGS }, \
	{ C_DNSSEC_POLICY,       YP_TREF,  YP_VREF = { C_POLICY }, FLAGS, { check_ref_dflt } }, \
	{ C_SERIAL_POLICY,       YP_TOPT,  YP_VOPT = { serial_policies, SERIAL_POLICY_INCREMENT } }, \
	{ C_REQUEST_EDNS_OPTION, YP_TDATA, YP_VDATA = { 0, NULL, edns_opt_to_bin, edns_opt_to_txt } }, \
	{ C_MAX_REFRESH_INTERVAL,YP_TINT,  YP_VINT = { 2, UINT32_MAX, UINT32_MAX, YP_STIME } }, \
	{ C_MIN_REFRESH_INTERVAL,YP_TINT,  YP_VINT = { 2, UINT32_MAX, 2, YP_STIME } }, \
	{ C_MODULE,              YP_TDATA, YP_VDATA = { 0, NULL, mod_id_to_bin, mod_id_to_txt }, \
	                                   YP_FMULTI | FLAGS, { check_modref } }, \
	{ C_COMMENT,             YP_TSTR,  YP_VNONE }, \

static const yp_item_t desc_template[] = {
	{ C_ID, YP_TSTR, YP_VNONE, CONF_IO_FREF },
	ZONE_ITEMS(CONF_IO_FRLD_ZONES)
	{ C_GLOBAL_MODULE,       YP_TDATA, YP_VDATA = { 0, NULL, mod_id_to_bin, mod_id_to_txt },
	                                   YP_FMULTI | CONF_IO_FRLD_MOD, { check_modref } },
	{ C_TIMER_DB,            YP_TSTR,  YP_VSTR = { "timers" }, CONF_IO_FRLD_ZONES },
	{ C_MAX_TIMER_DB_SIZE,   YP_TINT,  YP_VINT = { MEGA(1), VIRT_MEM_LIMIT(GIGA(100)),
	                                               MEGA(100), YP_SSIZE }, CONF_IO_FRLD_ZONES },
	{ C_JOURNAL_DB,          YP_TSTR,  YP_VSTR = { "journal" }, CONF_IO_FRLD_SRV },
	{ C_JOURNAL_DB_MODE,     YP_TOPT,  YP_VOPT = { journal_modes, JOURNAL_MODE_ROBUST },
	                                   CONF_IO_FRLD_SRV },
	{ C_MAX_JOURNAL_DB_SIZE, YP_TINT,  YP_VINT = { JOURNAL_MIN_FSLIMIT, VIRT_MEM_LIMIT(TERA(100)),
	                                               VIRT_MEM_LIMIT(GIGA(20)), YP_SSIZE },
	                                               CONF_IO_FRLD_SRV },
	{ C_KASP_DB,             YP_TSTR,  YP_VSTR = { "keys" }, CONF_IO_FRLD_SRV },
	{ C_MAX_KASP_DB_SIZE,    YP_TINT,  YP_VINT = { MEGA(5), VIRT_MEM_LIMIT(GIGA(100)),
	                                               MEGA(500), YP_SSIZE }, CONF_IO_FRLD_SRV },
	{ NULL }
};

static const yp_item_t desc_zone[] = {
	{ C_DOMAIN, YP_TDNAME, YP_VNONE, CONF_IO_FRLD_ZONE },
	{ C_TPL,    YP_TREF,   YP_VREF = { C_TPL }, CONF_IO_FRLD_ZONE, { check_ref } },
	ZONE_ITEMS(CONF_IO_FRLD_ZONE)
	{ NULL }
};

const yp_item_t conf_schema[] = {
	{ C_MODULE,   YP_TGRP, YP_VGRP = { desc_module }, YP_FMULTI | CONF_IO_FRLD_ALL |
	                                                  CONF_IO_FCHECK_ZONES, { load_module } },
	{ C_SRV,      YP_TGRP, YP_VGRP = { desc_server }, CONF_IO_FRLD_SRV, { check_server } },
	{ C_CTL,      YP_TGRP, YP_VGRP = { desc_control } },
	{ C_LOG,      YP_TGRP, YP_VGRP = { desc_log }, YP_FMULTI | CONF_IO_FRLD_LOG },
	{ C_STATS,    YP_TGRP, YP_VGRP = { desc_stats }, CONF_IO_FRLD_SRV },
	{ C_KEYSTORE, YP_TGRP, YP_VGRP = { desc_keystore }, YP_FMULTI, { check_keystore } },
	{ C_KEY,      YP_TGRP, YP_VGRP = { desc_key }, YP_FMULTI, { check_key } },
	{ C_ACL,      YP_TGRP, YP_VGRP = { desc_acl }, YP_FMULTI, { check_acl } },
	{ C_RMT,      YP_TGRP, YP_VGRP = { desc_remote }, YP_FMULTI, { check_remote } },
	{ C_SBM,      YP_TGRP, YP_VGRP = { desc_submission }, YP_FMULTI },
	{ C_POLICY,   YP_TGRP, YP_VGRP = { desc_policy }, YP_FMULTI, { check_policy } },
	{ C_TPL,      YP_TGRP, YP_VGRP = { desc_template }, YP_FMULTI, { check_template } },
	{ C_ZONE,     YP_TGRP, YP_VGRP = { desc_zone }, YP_FMULTI | CONF_IO_FZONE, { check_zone } },
	{ C_INCL,     YP_TSTR, YP_VNONE, CONF_IO_FDIFF_ZONES | CONF_IO_FRLD_ALL, { include_file } },
	{ NULL }
};
