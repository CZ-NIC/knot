/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <glob.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef ENABLE_XDP
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#endif

#include "libdnssec/key.h"
#include "knot/conf/tools.h"
#include "knot/conf/conf.h"
#include "knot/conf/module.h"
#include "knot/conf/schema.h"
#include "knot/common/log.h"
#include "libknot/errcode.h"
#include "libknot/yparser/yptrafo.h"
#include "libknot/xdp.h"
#include "contrib/sockaddr.h"
#include "contrib/string.h"
#include "contrib/wire_ctx.h"

#define MAX_INCLUDE_DEPTH	5

static bool is_default_id(
	const uint8_t *id,
	size_t id_len)
{
	return id_len == CONF_DEFAULT_ID[0] &&
	       memcmp(id, CONF_DEFAULT_ID + 1, id_len) == 0;
}

int conf_exec_callbacks(
	knotd_conf_check_args_t *args)
{
	if (args == NULL) {
		return KNOT_EINVAL;
	}

	for (size_t i = 0; i < YP_MAX_MISC_COUNT; i++) {
		int (*fcn)(knotd_conf_check_args_t *) = args->item->misc[i];
		if (fcn == NULL) {
			break;
		}

		int ret = fcn(args);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

int mod_id_to_bin(
	YP_TXT_BIN_PARAMS)
{
	YP_CHECK_PARAMS_BIN;

	// Check for "mod_name/mod_id" format.
	const uint8_t *pos = (uint8_t *)strchr((char *)in->position, '/');
	if (pos == in->position) {
		// Missing module name.
		return KNOT_EINVAL;
	} else if (pos >= stop - 1) {
		// Missing module identifier after slash.
		return KNOT_EINVAL;
	}

	// Write mod_name in the yp_name_t format.
	uint8_t name_len = (pos != NULL) ? (pos - in->position) :
	                                   wire_ctx_available(in);
	wire_ctx_write_u8(out, name_len);
	wire_ctx_write(out, in->position, name_len);
	wire_ctx_skip(in, name_len);

	// Check for mod_id.
	if (pos != NULL) {
		// Skip the separator.
		wire_ctx_skip(in, sizeof(uint8_t));

		// Write mod_id as a zero terminated string.
		int ret = yp_str_to_bin(in, out, stop);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	YP_CHECK_RET;
}

int mod_id_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	// Write mod_name.
	uint8_t name_len = wire_ctx_read_u8(in);
	wire_ctx_write(out, in->position, name_len);
	wire_ctx_skip(in, name_len);

	// Check for mod_id.
	if (wire_ctx_available(in) > 0) {
		// Write the separator.
		wire_ctx_write_u8(out, '/');

		// Write mod_id.
		int ret = yp_str_to_txt(in, out);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	YP_CHECK_RET;
}

int rrtype_to_bin(
	YP_TXT_BIN_PARAMS)
{
	YP_CHECK_PARAMS_BIN;

	uint16_t type;
	int ret = knot_rrtype_from_string((char *)in->position, &type);
	if (ret != 0) {
		return KNOT_EINVAL;
	}
	wire_ctx_write_u64(out, type);

	YP_CHECK_RET;
}

int rrtype_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	uint16_t type = (uint16_t)wire_ctx_read_u64(in);
	int ret = knot_rrtype_to_string(type, (char *)out->position, out->size);
	if (ret < 0) {
		return KNOT_EINVAL;
	}
	wire_ctx_skip(out, ret);

	YP_CHECK_RET;
}

int rdname_to_bin(
	YP_TXT_BIN_PARAMS)
{
	YP_CHECK_PARAMS_BIN;

	int ret = yp_dname_to_bin(in, out, stop);
	if (ret == KNOT_EOK && in->wire[in->size - 1] != '.') {
		// If non-FQDN, trim off the zero label.
		wire_ctx_skip(out, -1);
	}

	YP_CHECK_RET;
}

int rdname_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	// Temporarily normalize the input.
	if (in->wire[in->size - 1] == '\0') {
		return yp_dname_to_txt(in, out);
	}

	knot_dname_storage_t full_name;
	wire_ctx_t ctx = wire_ctx_init(full_name, sizeof(full_name));
	wire_ctx_write(&ctx, in->wire, in->size);
	wire_ctx_write(&ctx, "\0", 1);
	wire_ctx_set_offset(&ctx, 0);

	int ret = yp_dname_to_txt(&ctx, out);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Trim off the trailing dot.
	wire_ctx_skip(out, -1);

	YP_CHECK_RET;
}

int check_ref(
	knotd_conf_check_args_t *args)
{
	const yp_item_t *ref = args->item->var.r.ref;

	// Try to find a referenced block with the id.
	if (!conf_rawid_exists_txn(args->extra->conf, args->extra->txn, ref->name,
	                           args->data, args->data_len)) {
		args->err_str = "invalid reference";
		return KNOT_ENOENT;
	}

	return KNOT_EOK;
}

int check_ref_dflt(
	knotd_conf_check_args_t *args)
{
	if (check_ref(args) != KNOT_EOK && !is_default_id(args->data, args->data_len)) {
		args->err_str = "invalid reference";
		return KNOT_ENOENT;
	}

	return KNOT_EOK;
}

int check_listen(
	knotd_conf_check_args_t *args)
{
	bool no_port;
	struct sockaddr_storage ss = yp_addr(args->data, &no_port);
	if (!no_port && sockaddr_port(&ss) == 0) {
		args->err_str = "invalid port";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int check_xdp_listen_old(
	knotd_conf_check_args_t *args)
{
	CONF_LOG(LOG_NOTICE, "option 'server.listen-xdp' is obsolete, "
	                     "use option 'xdp.listen' instead");

	return KNOT_EOK;
}

int check_xdp_listen(
	knotd_conf_check_args_t *args)
{
#ifndef ENABLE_XDP
		args->err_str = "XDP is not available";
		return KNOT_ENOTSUP;
#else
	bool no_port;
	struct sockaddr_storage ss = yp_addr(args->data, &no_port);
	conf_xdp_iface_t if_new;
	int ret = conf_xdp_iface(&ss, &if_new);
	if (ret != KNOT_EOK) {
		args->err_str = "invalid XDP interface specification";
		return ret;
	}

	conf_val_t xdp = conf_get_txn(args->extra->conf, args->extra->txn, C_XDP,
	                              C_LISTEN);
	size_t count = conf_val_count(&xdp);
	while (xdp.code == KNOT_EOK && count-- > 1) {
		struct sockaddr_storage addr = conf_addr(&xdp, NULL);
		conf_xdp_iface_t if_prev;
		ret = conf_xdp_iface(&addr, &if_prev);
		if (ret != KNOT_EOK) {
			return ret;
		}
		if (strcmp(if_new.name, if_prev.name) == 0) {
			args->err_str = "duplicate XDP interface specification";
			return KNOT_EINVAL;
		}
		conf_val_next(&xdp);
	}

	return KNOT_EOK;
#endif
}

static int dir_exists(const char *dir)
{
	struct stat st;
	if (stat(dir, &st) != 0) {
		return knot_map_errno();
	} else if (!S_ISDIR(st.st_mode)) {
		return KNOT_ENOTDIR;
	} else if (access(dir, W_OK) != 0) {
		return knot_map_errno();
	} else {
		return KNOT_EOK;
	}
}

static int dir_can_create(const char *dir)
{
	int ret = dir_exists(dir);
	if (ret == KNOT_ENOENT) {
		return KNOT_EOK;
	} else {
		return ret;
	}
}

static void check_db(
	knotd_conf_check_args_t *args,
	const yp_name_t *db_type,
	int (*check_fun)(const char *),
	const char *desc)
{
	if (db_type != NULL) {
		conf_val_t val = conf_get_txn(args->extra->conf, args->extra->txn,
		                              C_DB, db_type);
		if (val.code != KNOT_EOK) {
			// Don't check implicit database values.
			return;
		}
	}

	char *db = conf_db_txn(args->extra->conf, args->extra->txn, db_type);
	int ret = check_fun(db);
	if (ret != KNOT_EOK) {
		CONF_LOG(LOG_WARNING, "%s '%s' %s", desc, db,
		         (ret == KNOT_EACCES ? "not writable" : knot_strerror(ret)));
	}
	free(db);
}

int check_database(
	knotd_conf_check_args_t *args)
{
	check_db(args, NULL,         dir_exists,     "database storage");
	check_db(args, C_TIMER_DB,   dir_can_create, "timer database");
	check_db(args, C_JOURNAL_DB, dir_can_create, "journal database");
	check_db(args, C_KASP_DB,    dir_can_create, "KASP database");
	check_db(args, C_CATALOG_DB, dir_can_create, "catalog database");

	return KNOT_EOK;
}

int check_modref(
	knotd_conf_check_args_t *args)
{
	const yp_name_t *mod_name = (const yp_name_t *)args->data;
	const uint8_t *id = args->data + 1 + args->data[0];
	size_t id_len = args->data_len - 1 - args->data[0];

	// Check if the module is ever available.
	const module_t *mod = conf_mod_find(args->extra->conf, mod_name + 1,
	                                    mod_name[0], args->extra->check);
	if (mod == NULL) {
		args->err_str = "unknown module";
		return KNOT_EINVAL;
	}

	// Check if the module requires some configuration.
	if (id_len == 0) {
		if (mod->api->flags & KNOTD_MOD_FLAG_OPT_CONF) {
			return KNOT_EOK;
		} else {
			args->err_str = "missing module configuration";
			return KNOT_YP_ENOID;
		}
	}

	// Try to find a module with the id.
	if (!conf_rawid_exists_txn(args->extra->conf, args->extra->txn, mod_name,
	                           id, id_len)) {
		args->err_str = "invalid module reference";
		return KNOT_ENOENT;
	}

	return KNOT_EOK;
}

int check_module_id(
	knotd_conf_check_args_t *args)
{
	const size_t len = strlen(KNOTD_MOD_NAME_PREFIX);

	if (strncmp((const char *)args->id, KNOTD_MOD_NAME_PREFIX, len) != 0) {
		args->err_str = "required 'mod-' prefix";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

#define CHECK_LEGACY_NAME(section, old_item, new_item) { \
	conf_val_t val = conf_get_txn(args->extra->conf, args->extra->txn, \
	                              section, old_item); \
	if (val.code == KNOT_EOK) { \
		CONF_LOG(LOG_NOTICE, "option '%s.%s' has no effect, " \
		                     "use option '%s.%s' instead", \
		                     &section[1], &old_item[1], \
		                     &section[1], &new_item[1]); \
	} \
}

#define CHECK_LEGACY_NAME_ID(section, old_item, new_item) { \
	conf_val_t val = conf_rawid_get_txn(args->extra->conf, args->extra->txn, \
	                                    section, old_item, args->id, args->id_len); \
	if (val.code == KNOT_EOK) { \
		CONF_LOG(LOG_NOTICE, "option '%s.%s' has no effect, " \
		                     "use option '%s.%s' instead", \
		                     &section[1], &old_item[1], \
		                     &section[1], &new_item[1]); \
	} \
}

static void check_mtu(knotd_conf_check_args_t *args, conf_val_t *xdp_listen)
{
#ifdef ENABLE_XDP
	conf_val_t val = conf_get_txn(args->extra->conf, args->extra->txn,
	                              C_SRV, C_UDP_MAX_PAYLOAD_IPV4);
	if (val.code != KNOT_EOK) {
		val = conf_get_txn(args->extra->conf, args->extra->txn,
		                   C_SRV, C_UDP_MAX_PAYLOAD);
	}
	int64_t ipv4_max = conf_int(&val) + sizeof(struct udphdr) + 4 + // Eth. CRC
	                   sizeof(struct iphdr) + sizeof(struct ethhdr);

	val = conf_get_txn(args->extra->conf, args->extra->txn,
	                   C_SRV, C_UDP_MAX_PAYLOAD_IPV6);
	if (val.code != KNOT_EOK) {
		val = conf_get_txn(args->extra->conf, args->extra->txn,
		                   C_SRV, C_UDP_MAX_PAYLOAD);
	}
	int64_t ipv6_max = conf_int(&val) + sizeof(struct udphdr) + 4 + // Eth. CRC
	                   sizeof(struct ipv6hdr) + sizeof(struct ethhdr);

	if (ipv6_max > KNOT_XDP_MAX_MTU || ipv4_max > KNOT_XDP_MAX_MTU) {
		CONF_LOG(LOG_WARNING, "maximum UDP payload not compatible with XDP MTU (%u)",
		         KNOT_XDP_MAX_MTU);
	}

	while (xdp_listen->code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(xdp_listen, NULL);
		conf_xdp_iface_t iface;
		int ret = conf_xdp_iface(&addr, &iface);
		if (ret != KNOT_EOK) {
			CONF_LOG(LOG_WARNING, "failed to check XDP interface MTU");
			return;
		}
		int mtu = knot_eth_mtu(iface.name);
		if (mtu < 0) {
			CONF_LOG(LOG_WARNING, "failed to read MTU of interface %s",
			         iface.name);
			continue;
		}
		mtu += sizeof(struct ethhdr) + 4;
		if (ipv6_max > mtu || ipv4_max > mtu) {
			CONF_LOG(LOG_WARNING, "maximum UDP payload not compatible "
			                      "with MTU of interface %s", iface.name);
		}
		conf_val_next(xdp_listen);
	}
#endif
}

int check_server(
	knotd_conf_check_args_t *args)
{
	CHECK_LEGACY_NAME(C_SRV, C_TCP_REPLY_TIMEOUT, C_TCP_RMT_IO_TIMEOUT);
	CHECK_LEGACY_NAME(C_SRV, C_MAX_TCP_CLIENTS, C_TCP_MAX_CLIENTS);
	CHECK_LEGACY_NAME(C_SRV, C_MAX_UDP_PAYLOAD, C_UDP_MAX_PAYLOAD);
	CHECK_LEGACY_NAME(C_SRV, C_MAX_IPV4_UDP_PAYLOAD, C_UDP_MAX_PAYLOAD_IPV4);
	CHECK_LEGACY_NAME(C_SRV, C_MAX_IPV6_UDP_PAYLOAD, C_UDP_MAX_PAYLOAD_IPV6);

	return KNOT_EOK;
}

int check_xdp(
	knotd_conf_check_args_t *args)
{
	conf_val_t xdp_listen = conf_get_txn(args->extra->conf, args->extra->txn,
	                                     C_XDP, C_LISTEN);
	conf_val_t srv_listen = conf_get_txn(args->extra->conf, args->extra->txn,
	                                     C_SRV, C_LISTEN);
	conf_val_t tcp = conf_get_txn(args->extra->conf, args->extra->txn, C_XDP,
	                              C_TCP);
	if (xdp_listen.code == KNOT_EOK) {
		if (srv_listen.code != KNOT_EOK && tcp.code != KNOT_EOK) {
			CONF_LOG(LOG_WARNING, "TCP processing not available");
		}
		check_mtu(args, &xdp_listen);
	}

	return KNOT_EOK;
}

int check_keystore(
	knotd_conf_check_args_t *args)
{
	conf_val_t backend = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_KEYSTORE,
	                                        C_BACKEND, args->id, args->id_len);
	conf_val_t config = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_KEYSTORE,
	                                       C_CONFIG, args->id, args->id_len);

	if (conf_opt(&backend) == KEYSTORE_BACKEND_PKCS11 && conf_str(&config) == NULL) {
		args->err_str = "no PKCS #11 configuration defined";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int check_policy(
	knotd_conf_check_args_t *args)
{
	conf_val_t sts = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
	                                    C_SINGLE_TYPE_SIGNING, args->id, args->id_len);
	conf_val_t alg = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
	                                    C_ALG, args->id, args->id_len);
	conf_val_t ksk = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
	                                    C_KSK_SIZE, args->id, args->id_len);
	conf_val_t zsk = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
	                                    C_ZSK_SIZE, args->id, args->id_len);
	conf_val_t lifetime = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
	                                    C_RRSIG_LIFETIME, args->id, args->id_len);
	conf_val_t refresh = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
	                                    C_RRSIG_REFRESH, args->id, args->id_len);
	conf_val_t prerefresh = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
	                                    C_RRSIG_PREREFRESH, args->id, args->id_len);
	conf_val_t prop_del = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
						 C_PROPAG_DELAY, args->id, args->id_len);
	conf_val_t zsk_life = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
						 C_ZSK_LIFETIME, args->id, args->id_len);
	conf_val_t ksk_life = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
						 C_KSK_LIFETIME, args->id, args->id_len);
	conf_val_t dnskey_ttl = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
						   C_DNSKEY_TTL, args->id, args->id_len);
	conf_val_t zone_max_ttl = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
						     C_ZONE_MAX_TLL, args->id, args->id_len);
	conf_val_t nsec3_iters = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
	                                            C_NSEC3_ITER, args->id, args->id_len);

	unsigned algorithm = conf_opt(&alg);
	if (algorithm == 3 || algorithm == 6) {
		args->err_str = "DSA algorithm no longer supported";
		return KNOT_EINVAL;
	}

	int64_t ksk_size = conf_int(&ksk);
	if (ksk_size != YP_NIL && !dnssec_algorithm_key_size_check(algorithm, ksk_size)) {
		args->err_str = "KSK key size not compatible with the algorithm";
		return KNOT_EINVAL;
	}

	int64_t zsk_size = conf_int(&zsk);
	if (zsk_size != YP_NIL && !dnssec_algorithm_key_size_check(algorithm, zsk_size)) {
		args->err_str = "ZSK key size not compatible with the algorithm";
		return KNOT_EINVAL;
	}

	int64_t lifetime_val = conf_int(&lifetime);
	int64_t refresh_val = conf_int(&refresh);
	int64_t preref_val = conf_int(&prerefresh);
	if (lifetime_val <= refresh_val + preref_val) {
		args->err_str = "RRSIG refresh + pre-refresh has to be lower than RRSIG lifetime";
		return KNOT_EINVAL;
	}

	bool sts_val = conf_bool(&sts);
	int64_t prop_del_val = conf_int(&prop_del);
	int64_t zsk_life_val = conf_int(&zsk_life);
	int64_t ksk_life_val = conf_int(&ksk_life);
	int64_t dnskey_ttl_val = conf_int(&dnskey_ttl);
	if (dnskey_ttl_val == YP_NIL) {
		dnskey_ttl_val = 0;
	}
	int64_t zone_max_ttl_val = conf_int(&zone_max_ttl);
	if (zone_max_ttl_val == YP_NIL) {
		zone_max_ttl_val = dnskey_ttl_val; // Better than 0.
	}

	if (sts_val) {
		if (ksk_life_val != 0 && ksk_life_val < 2 * prop_del_val + dnskey_ttl_val + zone_max_ttl_val) {
			args->err_str = "CSK lifetime too low according to propagation delay, DNSKEY TTL, "
			                "and maximum zone TTL";
			return KNOT_EINVAL;
		}
	} else {
		if (ksk_life_val != 0 && ksk_life_val < 2 * prop_del_val + 2 * dnskey_ttl_val) {
			args->err_str = "KSK lifetime too low according to propagation delay and DNSKEY TTL";
			return KNOT_EINVAL;
		}
		if (zsk_life_val != 0 && zsk_life_val < 2 * prop_del_val + dnskey_ttl_val + zone_max_ttl_val) {
			args->err_str = "ZSK lifetime too low according to propagation delay, DNSKEY TTL, "
			                "and maximum zone TTL";
			return KNOT_EINVAL;
		}
	}

	conf_val_t cds_cdnskey = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
	                                            C_CDS_CDNSKEY, args->id, args->id_len);
	conf_val_t ds_push = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
	                                        C_DS_PUSH, args->id, args->id_len);

	if (conf_val_count(&ds_push) > 0 && conf_opt(&cds_cdnskey) == CDS_CDNSKEY_NONE) {
		args->err_str = "DS push requires enabled CDS/CDNSKEY publication";
		return KNOT_EINVAL;
	}

#ifndef HAVE_GNUTLS_REPRODUCIBLE
	conf_val_t repro_sign = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_POLICY,
	                                           C_REPRO_SIGNING, args->id, args->id_len);
	if (conf_bool(&repro_sign)) {
		CONF_LOG(LOG_WARNING, "reproducible signing not available, signing normally");
	}
#endif

	uint16_t iters = conf_int(&nsec3_iters);
	if (iters > 20) {
		CONF_LOG(LOG_NOTICE, "policy[%s].nsec3-iterations=%u is too high, "
		                     "recommended value is 0-10", args->id, iters);
	}

	return KNOT_EOK;
}

int check_key(
	knotd_conf_check_args_t *args)
{
	conf_val_t alg = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_KEY,
	                                    C_ALG, args->id, args->id_len);
	if (conf_val_count(&alg) == 0) {
		args->err_str = "no key algorithm defined";
		return KNOT_EINVAL;
	}

	conf_val_t secret = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_KEY,
	                                       C_SECRET, args->id, args->id_len);
	if (conf_val_count(&secret) == 0) {
		args->err_str = "no key secret defined";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int check_acl(
	knotd_conf_check_args_t *args)
{
	conf_val_t action = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_ACL,
	                                       C_ACTION, args->id, args->id_len);
	conf_val_t deny = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_ACL,
	                                     C_DENY, args->id, args->id_len);
	if (conf_val_count(&action) == 0 && conf_val_count(&deny) == 0) {
		args->err_str = "no ACL action defined";
		return KNOT_EINVAL;
	}

	conf_val_t addr = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_ACL,
	                                     C_ADDR, args->id, args->id_len);
	conf_val_t key = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_ACL,
	                                    C_KEY, args->id, args->id_len);
	conf_val_t remote = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_ACL,
	                                       C_RMT, args->id, args->id_len);
	if (remote.code != KNOT_ENOENT &&
	    (addr.code != KNOT_ENOENT || key.code != KNOT_ENOENT)) {
		args->err_str = "specified ACL/remote together with address or key";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int check_remote(
	knotd_conf_check_args_t *args)
{
	conf_val_t addr = conf_rawid_get_txn(args->extra->conf, args->extra->txn, C_RMT,
	                                     C_ADDR, args->id, args->id_len);
	if (conf_val_count(&addr) == 0) {
		args->err_str = "no remote address defined";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

#define CHECK_LEGACY_MOVED(old_item, new_item) { \
	conf_val_t val = conf_rawid_get_txn(args->extra->conf, args->extra->txn, \
	                                    C_TPL, old_item, args->id, args->id_len); \
	if (val.code == KNOT_EOK) { \
		CONF_LOG(LOG_NOTICE, "option 'template.%s' has no effect, " \
		                     "use option 'database.%s' instead", \
		                     &old_item[1], &new_item[1]); \
	} \
}

#define CHECK_DFLT(item, name) { \
	conf_val_t val = conf_rawid_get_txn(args->extra->conf, args->extra->txn, \
	                                    C_TPL, item, args->id, args->id_len); \
	if (val.code == KNOT_EOK) { \
		args->err_str = name " in non-default template"; \
		return KNOT_EINVAL; \
	} \
}

int check_catalog_group(
	knotd_conf_check_args_t *args)
{
	assert(args->data_len > 0);
	if (args->data_len - 1 > 255) {
		args->err_str = "group name longer than 255 characters";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int check_template(
	knotd_conf_check_args_t *args)
{
	CHECK_LEGACY_MOVED(C_TIMER_DB, C_TIMER_DB);
	CHECK_LEGACY_MOVED(C_MAX_TIMER_DB_SIZE, C_TIMER_DB_MAX_SIZE);
	CHECK_LEGACY_MOVED(C_JOURNAL_DB, C_JOURNAL_DB);
	CHECK_LEGACY_MOVED(C_JOURNAL_DB_MODE, C_JOURNAL_DB_MODE);
	CHECK_LEGACY_MOVED(C_MAX_JOURNAL_DB_SIZE, C_JOURNAL_DB_MAX_SIZE);
	CHECK_LEGACY_MOVED(C_KASP_DB, C_KASP_DB);
	CHECK_LEGACY_MOVED(C_MAX_KASP_DB_SIZE, C_KASP_DB_MAX_SIZE);

	CHECK_LEGACY_NAME_ID(C_TPL, C_MAX_ZONE_SIZE, C_ZONE_MAX_SIZE);
	CHECK_LEGACY_NAME_ID(C_TPL, C_MAX_REFRESH_INTERVAL, C_REFRESH_MAX_INTERVAL);
	CHECK_LEGACY_NAME_ID(C_TPL, C_MIN_REFRESH_INTERVAL, C_REFRESH_MIN_INTERVAL);
	CHECK_LEGACY_NAME_ID(C_TPL, C_MAX_JOURNAL_DEPTH, C_JOURNAL_MAX_DEPTH);
	CHECK_LEGACY_NAME_ID(C_TPL, C_MAX_JOURNAL_USAGE, C_JOURNAL_MAX_USAGE);

	if (!is_default_id(args->id, args->id_len)) {
		CHECK_DFLT(C_GLOBAL_MODULE, "global module");
	}

	return KNOT_EOK;
}

int check_zone(
	knotd_conf_check_args_t *args)
{
	CHECK_LEGACY_NAME_ID(C_ZONE, C_MAX_ZONE_SIZE, C_ZONE_MAX_SIZE);
	CHECK_LEGACY_NAME_ID(C_ZONE, C_MAX_REFRESH_INTERVAL, C_REFRESH_MAX_INTERVAL);
	CHECK_LEGACY_NAME_ID(C_ZONE, C_MIN_REFRESH_INTERVAL, C_REFRESH_MIN_INTERVAL);
	CHECK_LEGACY_NAME_ID(C_ZONE, C_MAX_JOURNAL_DEPTH, C_JOURNAL_MAX_DEPTH);
	CHECK_LEGACY_NAME_ID(C_ZONE, C_MAX_JOURNAL_USAGE, C_JOURNAL_MAX_USAGE);

	conf_val_t zf_load = conf_zone_get_txn(args->extra->conf, args->extra->txn,
	                                       C_ZONEFILE_LOAD, yp_dname(args->id));
	conf_val_t journal = conf_zone_get_txn(args->extra->conf, args->extra->txn,
	                                       C_JOURNAL_CONTENT, yp_dname(args->id));
	if (conf_opt(&zf_load) == ZONEFILE_LOAD_DIFSE &&
	    conf_opt(&journal) != JOURNAL_CONTENT_ALL) {
		args->err_str = "'zonefile-load: difference-no-serial' requires 'journal-content: all'";
		return KNOT_EINVAL;
	}

	conf_val_t signing = conf_zone_get_txn(args->extra->conf, args->extra->txn,
	                                       C_DNSSEC_SIGNING, yp_dname(args->id));
	conf_val_t validation = conf_zone_get_txn(args->extra->conf, args->extra->txn,
	                                          C_DNSSEC_VALIDATION, yp_dname(args->id));
	if (conf_bool(&signing) == true && conf_bool(&validation) == true) {
		args->err_str = "'dnssec-validation' is not compatible with 'dnssec-signing'";
		return KNOT_EINVAL;
	}

	conf_val_t catalog_role = conf_zone_get_txn(args->extra->conf, args->extra->txn,
	                                            C_CATALOG_ROLE, yp_dname(args->id));
	conf_val_t catalog_tpl = conf_zone_get_txn(args->extra->conf, args->extra->txn,
	                                           C_CATALOG_TPL, yp_dname(args->id));
	conf_val_t catalog_zone = conf_zone_get_txn(args->extra->conf, args->extra->txn,
	                                            C_CATALOG_ZONE, yp_dname(args->id));
	if ((bool)(conf_opt(&catalog_role) == CATALOG_ROLE_INTERPRET) !=
	    (bool)(catalog_tpl.code == KNOT_EOK)) {
		args->err_str = "'catalog-role' must correspond to configured 'catalog-template'";
		return KNOT_EINVAL;
	}
	if ((bool)(conf_opt(&catalog_role) == CATALOG_ROLE_MEMBER) !=
	    (bool)(catalog_zone.code == KNOT_EOK)) {
		args->err_str = "'catalog-role' must correspond to configured 'catalog-zone'";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int glob_error(
	const char *epath,
	int eerrno)
{
	CONF_LOG(LOG_WARNING, "failed to access '%s' (%s)", epath,
	         knot_strerror(knot_map_errno_code(eerrno)));

	return 0;
}

int include_file(
	knotd_conf_check_args_t *args)
{
	if (args->data_len == 0) {
		return KNOT_YP_ENODATA;
	}

	// This function should not be called in more threads.
	static int depth = 0;
	glob_t glob_buf = { 0 };
	char *path = NULL;
	int ret;

	// Check for include loop.
	if (depth++ > MAX_INCLUDE_DEPTH) {
		CONF_LOG(LOG_ERR, "include loop detected");
		ret = KNOT_EPARSEFAIL;
		goto include_error;
	}

	// Prepare absolute include path.
	if (args->data[0] == '/') {
		path = sprintf_alloc("%.*s", (int)args->data_len, args->data);
	} else {
		const char *file_name = args->extra->file_name != NULL ?
		                        args->extra->file_name : "./";
		char *full_current_name = realpath(file_name, NULL);
		if (full_current_name == NULL) {
			ret = KNOT_ENOMEM;
			goto include_error;
		}

		path = sprintf_alloc("%s/%.*s", dirname(full_current_name),
		                     (int)args->data_len, args->data);
		free(full_current_name);
	}
	if (path == NULL) {
		ret = KNOT_ESPACE;
		goto include_error;
	}

	// Evaluate include pattern (empty wildcard match is also valid).
	ret = glob(path, 0, glob_error, &glob_buf);
	if (ret != 0 && (ret != GLOB_NOMATCH || strchr(path, '*') == NULL)) {
		ret = KNOT_EFILE;
		goto include_error;
	}

	// Process glob result.
	for (size_t i = 0; i < glob_buf.gl_pathc; i++) {
		// Get file status.
		struct stat file_stat;
		if (stat(glob_buf.gl_pathv[i], &file_stat) != 0) {
			CONF_LOG(LOG_WARNING, "failed to get file status for '%s'",
			         glob_buf.gl_pathv[i]);
			continue;
		}

		// Ignore directory or non-regular file.
		if (S_ISDIR(file_stat.st_mode)) {
			continue;
		} else if (!S_ISREG(file_stat.st_mode)) {
			CONF_LOG(LOG_WARNING, "invalid include file '%s'",
			         glob_buf.gl_pathv[i]);
			continue;
		}

		// Include regular file.
		ret = conf_parse(args->extra->conf, args->extra->txn,
		                 glob_buf.gl_pathv[i], true);
		if (ret != KNOT_EOK) {
			goto include_error;
		}
	}

	ret = KNOT_EOK;
include_error:
	globfree(&glob_buf);
	free(path);
	depth--;

	return ret;
}

int load_module(
	knotd_conf_check_args_t *args)
{
	conf_val_t val = conf_rawid_get_txn(args->extra->conf, args->extra->txn,
	                                    C_MODULE, C_FILE, args->id, args->id_len);
	const char *file_name = conf_str(&val);

	char *mod_name = strndup((const char *)args->id, args->id_len);
	if (mod_name == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = conf_mod_load_extra(args->extra->conf, mod_name, file_name,
	                              args->extra->check);
	free(mod_name);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Update currently iterating item.
	const yp_item_t *section = yp_schema_find(C_MODULE, NULL, args->extra->conf->schema);
	assert(section);
	args->item = section->var.g.id;

	return ret;
}
