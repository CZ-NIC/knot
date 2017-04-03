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
#include <limits.h>
#ifndef PATH_MAX
  #define PATH_MAX 4096
#endif

#include "dnssec/key.h"
#include "knot/conf/tools.h"
#include "knot/conf/conf.h"
#include "knot/conf/scheme.h"
#include "knot/common/log.h"
#include "knot/nameserver/query_module.h"
#include "libknot/errcode.h"
#include "libknot/yparser/yptrafo.h"
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
	conf_check_t *args)
{
	if (args == NULL) {
		return KNOT_EINVAL;
	}

	for (size_t i = 0; i < YP_MAX_MISC_COUNT; i++) {
		int (*fcn)(conf_check_t *) = args->item->misc[i];
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

int edns_opt_to_bin(
	YP_TXT_BIN_PARAMS)
{
	YP_CHECK_PARAMS_BIN;

	// Check for "code:[value]" format.
	const uint8_t *pos = (uint8_t *)strchr((char *)in->position, ':');
	if (pos == NULL || pos >= stop) {
		return KNOT_EINVAL;
	}

	// Write option code.
	int ret = yp_int_to_bin(in, out, pos, 0, UINT16_MAX, YP_SNONE);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Skip the separator.
	wire_ctx_skip(in, sizeof(uint8_t));

	// Write option data.
	ret = yp_hex_to_bin(in, out, stop);
	if (ret != KNOT_EOK) {
		return ret;
	}

	YP_CHECK_RET;
}

int edns_opt_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	// Write option code.
	int ret = yp_int_to_txt(in, out, YP_SNONE);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Write the separator.
	wire_ctx_write_u8(out, ':');

	// Write option data.
	ret = yp_hex_to_txt(in, out);
	if (ret != KNOT_EOK) {
		return ret;
	}

	YP_CHECK_RET;
}

int addr_range_to_bin(
	YP_TXT_BIN_PARAMS)
{
	YP_CHECK_PARAMS_BIN;

	// Format: 0 - single address, 1 - address prefix, 2 - address range.
	uint8_t format = 0;

	// Check for the "addr/mask" format.
	const uint8_t *pos = (uint8_t *)strchr((char *)in->position, '/');
	if (pos >= stop) {
		pos = NULL;
	}

	if (pos != NULL) {
		format = 1;
	} else {
		// Check for the "addr1-addr2" format.
		pos = (uint8_t *)strchr((char *)in->position, '-');
		if (pos >= stop) {
			pos = NULL;
		}
		if (pos != NULL) {
			format = 2;
		}
	}

	// Store address1 type position.
	uint8_t *type1 = out->position;

	// Write the first address.
	int ret = yp_addr_noport_to_bin(in, out, pos, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	wire_ctx_write_u8(out, format);

	switch (format) {
	case 1:
		// Skip the separator.
		wire_ctx_skip(in, sizeof(uint8_t));

		// Write the prefix length.
		ret = yp_int_to_bin(in, out, stop, 0, (*type1 == 4) ? 32 : 128,
		                    YP_SNONE);
		if (ret != KNOT_EOK) {
			return ret;
		}
		break;
	case 2:
		// Skip the separator.
		wire_ctx_skip(in, sizeof(uint8_t));

		// Store address2 type position.
		uint8_t *type2 = out->position;

		// Write the second address.
		ret = yp_addr_noport_to_bin(in, out, stop, false);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Check for address mismatch.
		if (*type1 != *type2) {
			return KNOT_EINVAL;
		}
		break;
	default:
		break;
	}

	YP_CHECK_RET;
}

int addr_range_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	// Write the first address.
	int ret = yp_addr_noport_to_txt(in, out);
	if (ret != KNOT_EOK) {
		return ret;
	}

	uint8_t format = wire_ctx_read_u8(in);

	switch (format) {
	case 1:
		// Write the separator.
		wire_ctx_write_u8(out, '/');

		// Write the prefix length.
		ret = yp_int_to_txt(in, out, YP_SNONE);
		if (ret != KNOT_EOK) {
			return ret;
		}
		break;
	case 2:
		// Write the separator.
		wire_ctx_write_u8(out, '-');

		// Write the second address.
		ret = yp_addr_noport_to_txt(in, out);
		if (ret != KNOT_EOK) {
			return ret;
		}
		break;
	default:
		break;
	}

	YP_CHECK_RET;
}

int check_ref(
	conf_check_t *args)
{
	const yp_item_t *ref = args->item->var.r.ref;

	// Try to find a referenced block with the id.
	if (!conf_rawid_exists_txn(args->conf, args->txn, ref->name, args->data,
	                           args->data_len)) {
		args->err_str = "invalid reference";
		return KNOT_ENOENT;
	}

	return KNOT_EOK;
}

int check_ref_dflt(
	conf_check_t *args)
{
	if (check_ref(args) != KNOT_EOK && !is_default_id(args->data, args->data_len)) {
		args->err_str = "invalid reference";
		return KNOT_ENOENT;
	}

	return KNOT_EOK;
}

int check_modref(
	conf_check_t *args)
{
	const yp_name_t *mod_name = (const yp_name_t *)args->data;
	const uint8_t *id = args->data + 1 + args->data[0];
	size_t id_len = args->data_len - 1 - args->data[0];

	// Check if the module requires some configuration.
	if (id_len == 0) {
		static_module_t *mod = find_module(mod_name);
		if (mod == NULL) {
			return KNOT_EINVAL;
		}

		return mod->opt_conf ? KNOT_EOK : KNOT_YP_ENOID;
	}

	// Try to find a module with the id.
	if (!conf_rawid_exists_txn(args->conf, args->txn, mod_name, id, id_len)) {
		args->err_str = "invalid module reference";
		return KNOT_ENOENT;
	}

	return KNOT_EOK;
}

int check_server(
	conf_check_t *args)
{
	bool present = false;

	conf_val_t val;
	val = conf_get_txn(args->conf, args->txn, C_SRV, C_RATE_LIMIT);
	if (val.code == KNOT_EOK) {
		present = true;
	}

	val = conf_get_txn(args->conf, args->txn, C_SRV, C_RATE_LIMIT_SLIP);
	if (val.code == KNOT_EOK) {
		present = true;
	}

	val = conf_get_txn(args->conf, args->txn, C_SRV, C_RATE_LIMIT_TBL_SIZE);
	if (val.code == KNOT_EOK) {
		present = true;
	}

	val = conf_get_txn(args->conf, args->txn, C_SRV, C_RATE_LIMIT_WHITELIST);
	if (val.code == KNOT_EOK) {
		present = true;
	}

	if (present) {
		CONF_LOG(LOG_NOTICE, "obsolete RRL configuration in the server, "
		                     "use module mod-rrl instead");
	}

	return KNOT_EOK;
}

int check_keystore(
	conf_check_t *args)
{
	conf_val_t backend = conf_rawid_get_txn(args->conf, args->txn, C_KEYSTORE,
	                                        C_BACKEND, args->id, args->id_len);
	conf_val_t config = conf_rawid_get_txn(args->conf, args->txn, C_KEYSTORE,
	                                       C_CONFIG, args->id, args->id_len);

	if (conf_opt(&backend) == KEYSTORE_BACKEND_PKCS11 && conf_str(&config) == NULL) {
		args->err_str = "no PKCS #11 configuration defined";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int check_policy(
	conf_check_t *args)
{
	conf_val_t alg = conf_rawid_get_txn(args->conf, args->txn, C_POLICY,
	                                    C_ALG, args->id, args->id_len);
	conf_val_t ksk = conf_rawid_get_txn(args->conf, args->txn, C_POLICY,
	                                    C_KSK_SIZE, args->id, args->id_len);
	conf_val_t zsk = conf_rawid_get_txn(args->conf, args->txn, C_POLICY,
	                                    C_ZSK_SIZE, args->id, args->id_len);
	conf_val_t lifetime = conf_rawid_get_txn(args->conf, args->txn, C_POLICY,
	                                    C_RRSIG_LIFETIME, args->id, args->id_len);
	conf_val_t refresh = conf_rawid_get_txn(args->conf, args->txn, C_POLICY,
	                                    C_RRSIG_REFRESH, args->id, args->id_len);

	int64_t ksk_size = conf_int(&ksk);
	if (ksk_size != YP_NIL && !dnssec_algorithm_key_size_check(conf_opt(&alg), ksk_size)) {
		args->err_str = "KSK key size not compatible with the algorithm";
		return KNOT_EINVAL;
	}

	int64_t zsk_size = conf_int(&zsk);
	if (zsk_size != YP_NIL && !dnssec_algorithm_key_size_check(conf_opt(&alg), zsk_size)) {
		args->err_str = "ZSK key size not compatible with the algorithm";
		return KNOT_EINVAL;
	}

	int64_t lifetime_val = conf_int(&lifetime);
	int64_t refresh_val = conf_int(&refresh);
	if (lifetime_val <= refresh_val) {
		args->err_str = "RRSIG lifetime is supposed to be lower than refresh";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int check_key(
	conf_check_t *args)
{
	conf_val_t alg = conf_rawid_get_txn(args->conf, args->txn, C_KEY,
	                                    C_ALG, args->id, args->id_len);
	if (conf_val_count(&alg) == 0) {
		args->err_str = "no key algorithm defined";
		return KNOT_EINVAL;
	}

	conf_val_t secret = conf_rawid_get_txn(args->conf, args->txn, C_KEY,
	                                       C_SECRET, args->id, args->id_len);
	if (conf_val_count(&secret) == 0) {
		args->err_str = "no key secret defined";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int check_acl(
	conf_check_t *args)
{
	conf_val_t action = conf_rawid_get_txn(args->conf, args->txn, C_ACL,
	                                       C_ACTION, args->id, args->id_len);
	conf_val_t deny = conf_rawid_get_txn(args->conf, args->txn, C_ACL,
	                                     C_DENY, args->id, args->id_len);
	if (conf_val_count(&action) == 0 && conf_val_count(&deny) == 0) {
		args->err_str = "no ACL action defined";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int check_remote(
	conf_check_t *args)
{
	conf_val_t addr = conf_rawid_get_txn(args->conf, args->txn, C_RMT,
	                                     C_ADDR, args->id, args->id_len);
	if (conf_val_count(&addr) == 0) {
		args->err_str = "no remote address defined";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int check_template(
	conf_check_t *args)
{
	// Stop if the default template.
	if (is_default_id(args->id, args->id_len)) {
		return KNOT_EOK;
	}

	conf_val_t val;
	#define CHECK_DFLT(item, name) \
		val = conf_rawid_get_txn(args->conf, args->txn, C_TPL, item, \
		                         args->id, args->id_len); \
		if (val.code == KNOT_EOK) { \
			args->err_str = name " in non-default template"; \
			return KNOT_EINVAL; \
		}

	CHECK_DFLT(C_TIMER_DB, "timer database");
	CHECK_DFLT(C_GLOBAL_MODULE, "global module");
	CHECK_DFLT(C_JOURNAL_DB, "journal database path");
	CHECK_DFLT(C_JOURNAL_DB_MODE, "journal database mode");
	CHECK_DFLT(C_MAX_JOURNAL_DB_SIZE, "journal database maximum size");

	return KNOT_EOK;
}

int check_zone(
	conf_check_t *args)
{
	conf_val_t master = conf_zone_get_txn(args->conf, args->txn,
	                                      C_MASTER, args->id);
	conf_val_t dnssec = conf_zone_get_txn(args->conf, args->txn,
	                                      C_DNSSEC_SIGNING, args->id);

	// DNSSEC signing is not possible with slave zone.
	if (conf_val_count(&master) > 0 && conf_bool(&dnssec)) {
		args->err_str = "slave zone with DNSSEC signing";
		return KNOT_EINVAL;
	}

	conf_val_t signing = conf_zone_get_txn(args->conf, args->txn,
	                                       C_DNSSEC_SIGNING, args->id);
	conf_val_t policy = conf_zone_get_txn(args->conf, args->txn,
	                                       C_DNSSEC_POLICY, args->id);
	if (conf_bool(&signing) && policy.code != KNOT_EOK) {
		CONF_LOG(LOG_NOTICE, "DNSSEC policy settings in KASP database "
		         "is obsolete and will be removed in the next major release, "
		         "use zone.dnssec-policy in server configuration instead");
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
	conf_check_t *args)
{
	// This function should not be called in more threads.
	static int depth = 0;
	glob_t glob_buf = { 0 };
	int ret;

	char *path = malloc(PATH_MAX);
	if (path == NULL) {
		return KNOT_ENOMEM;
	}

	// Check for include loop.
	if (depth++ > MAX_INCLUDE_DEPTH) {
		CONF_LOG(LOG_ERR, "include loop detected");
		ret = KNOT_EPARSEFAIL;
		goto include_error;
	}

	// Prepare absolute include path.
	if (args->data[0] == '/') {
		ret = snprintf(path, PATH_MAX, "%.*s",
		               (int)args->data_len, args->data);
	} else {
		const char *file_name = args->file_name != NULL ?
		                        args->file_name : "./";
		char *full_current_name = realpath(file_name, NULL);
		if (full_current_name == NULL) {
			ret = KNOT_ENOMEM;
			goto include_error;
		}

		ret = snprintf(path, PATH_MAX, "%s/%.*s",
		               dirname(full_current_name),
		               (int)args->data_len, args->data);
		free(full_current_name);
	}
	if (ret <= 0 || ret >= PATH_MAX) {
		ret = KNOT_ESPACE;
		goto include_error;
	}

	// Evaluate include pattern.
	ret = glob(path, 0, glob_error, &glob_buf);
	if (ret != 0) {
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
		ret = conf_parse(args->conf, args->txn, glob_buf.gl_pathv[i], true);
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
