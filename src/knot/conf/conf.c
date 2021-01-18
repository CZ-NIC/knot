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

#include <assert.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include "knot/conf/base.h"
#include "knot/conf/confdb.h"
#include "knot/common/log.h"
#include "knot/server/dthreads.h"
#include "knot/zone/catalog.h"
#include "libknot/libknot.h"
#include "libknot/yparser/yptrafo.h"
#include "contrib/macros.h"
#include "contrib/sockaddr.h"
#include "contrib/strtonum.h"
#include "contrib/string.h"
#include "contrib/wire_ctx.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/openbsd/strlcpy.h"

#define DBG_LOG(err) CONF_LOG(LOG_DEBUG, "%s (%s)", __func__, knot_strerror((err)));

#define DFLT_TCP_WORKERS_MIN		10
#define DFLT_BG_WORKERS_MAX		10
#define FALLBACK_MAX_TCP_CLIENTS	100

bool conf_db_exists(
	const char *db_dir)
{
	if (db_dir == NULL) {
		return false;
	}

	struct stat st;
	char data_mdb[strlen(db_dir) + 10];
	(void)snprintf(data_mdb, sizeof(data_mdb), "%s/data.mdb", db_dir);
	return (stat(data_mdb, &st) == 0 && st.st_size > 0);
}

conf_val_t conf_get_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name)
{
	conf_val_t val = { NULL };

	if (key0_name == NULL || key1_name == NULL) {
		val.code = KNOT_EINVAL;
		DBG_LOG(val.code);
		return val;
	}

	conf_db_get(conf, txn, key0_name, key1_name, NULL, 0, &val);
	switch (val.code) {
	default:
		CONF_LOG(LOG_ERR, "failed to read '%s/%s' (%s)",
		         key0_name + 1, key1_name + 1, knot_strerror(val.code));
		// FALLTHROUGH
	case KNOT_EOK:
	case KNOT_ENOENT:
		return val;
	}
}

conf_val_t conf_rawid_get_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name,
	const uint8_t *id,
	size_t id_len)
{
	conf_val_t val = { NULL };

	if (key0_name == NULL || key1_name == NULL || id == NULL) {
		val.code = KNOT_EINVAL;
		DBG_LOG(val.code);
		return val;
	}

	conf_db_get(conf, txn, key0_name, key1_name, id, id_len, &val);
	switch (val.code) {
	default:
		CONF_LOG(LOG_ERR, "failed to read '%s/%s' with identifier (%s)",
		         key0_name + 1, key1_name + 1, knot_strerror(val.code));
		// FALLTHROUGH
	case KNOT_EOK:
	case KNOT_ENOENT:
	case KNOT_YP_EINVAL_ID:
		return val;
	}
}

conf_val_t conf_id_get_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name,
	conf_val_t *id)
{
	conf_val_t val = { NULL };

	if (key0_name == NULL || key1_name == NULL || id == NULL ||
	    id->code != KNOT_EOK) {
		val.code = KNOT_EINVAL;
		DBG_LOG(val.code);
		return val;
	}

	conf_val(id);

	conf_db_get(conf, txn, key0_name, key1_name, id->data, id->len, &val);
	switch (val.code) {
	default:
		CONF_LOG(LOG_ERR, "failed to read '%s/%s' with identifier (%s)",
		         key0_name + 1, key1_name + 1, knot_strerror(val.code));
		// FALLTHROUGH
	case KNOT_EOK:
	case KNOT_ENOENT:
	case KNOT_YP_EINVAL_ID:
		return val;
	}
}

conf_val_t conf_mod_get_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key1_name,
	const conf_mod_id_t *mod_id)
{
	conf_val_t val = { NULL };

	if (key1_name == NULL || mod_id == NULL) {
		val.code = KNOT_EINVAL;
		DBG_LOG(val.code);
		return val;
	}

	conf_db_get(conf, txn, mod_id->name, key1_name, mod_id->data, mod_id->len,
	            &val);
	switch (val.code) {
	default:
		CONF_LOG(LOG_ERR, "failed to read '%s/%s' (%s)",
		         mod_id->name + 1, key1_name + 1, knot_strerror(val.code));
		// FALLTHROUGH
	case KNOT_EOK:
	case KNOT_ENOENT:
	case KNOT_YP_EINVAL_ID:
		return val;
	}
}

conf_val_t conf_zone_get_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key1_name,
	const knot_dname_t *dname)
{
	conf_val_t val = { NULL };

	if (key1_name == NULL || dname == NULL) {
		val.code = KNOT_EINVAL;
		DBG_LOG(val.code);
		return val;
	}

	size_t dname_size = knot_dname_size(dname);

	// Try to get explicit value.
	conf_db_get(conf, txn, C_ZONE, key1_name, dname, dname_size, &val);
	switch (val.code) {
	case KNOT_EOK:
		return val;
	default:
		CONF_LOG_ZONE(LOG_ERR, dname, "failed to read '%s/%s' (%s)",
		              &C_ZONE[1], &key1_name[1], knot_strerror(val.code));
		// FALLTHROUGH
	case KNOT_YP_EINVAL_ID:
	case KNOT_ENOENT:
		break;
	}

	// Check if a template is available.
	conf_db_get(conf, txn, C_ZONE, C_TPL, dname, dname_size, &val);
	switch (val.code) {
	case KNOT_EOK:
		// Use the specified template.
		conf_val(&val);
		conf_db_get(conf, txn, C_TPL, key1_name, val.data, val.len, &val);
		goto got_template;
	default:
		CONF_LOG_ZONE(LOG_ERR, dname, "failed to read '%s/%s' (%s)",
		              &C_ZONE[1], &C_TPL[1], knot_strerror(val.code));
		// FALLTHROUGH
	case KNOT_ENOENT:
	case KNOT_YP_EINVAL_ID:
		break;
	}

	// Check if this is a catalog member zone.
	if (conf->catalog != NULL) {
		knot_dname_storage_t catalog;
		int ret = catalog_get_zone_threadsafe(conf->catalog, dname, catalog);
		if (ret == KNOT_EOK) {
			conf_db_get(conf, txn, C_ZONE, C_CATALOG_TPL, catalog,
			            knot_dname_size(catalog), &val);
			if (val.code != KNOT_EOK) {
				CONF_LOG_ZONE(LOG_ERR, catalog,
				              "catalog zone has no catalog template (%s)",
				              knot_strerror(val.code));
				return val;
			}
			conf_val(&val);
			conf_db_get(conf, txn, C_TPL, key1_name, val.data, val.len, &val);
			goto got_template;
		}
	}

	// Use the default template.
	conf_db_get(conf, txn, C_TPL, key1_name, CONF_DEFAULT_ID + 1,
	            CONF_DEFAULT_ID[0], &val);

got_template:
	switch (val.code) {
	default:
		CONF_LOG_ZONE(LOG_ERR, dname, "failed to read '%s/%s' (%s)",
		              &C_TPL[1], &key1_name[1], knot_strerror(val.code));
		// FALLTHROUGH
	case KNOT_EOK:
	case KNOT_ENOENT:
	case KNOT_YP_EINVAL_ID:
		break;
	}

	return val;
}

conf_val_t conf_default_get_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key1_name)
{
	conf_val_t val = { NULL };

	if (key1_name == NULL) {
		val.code = KNOT_EINVAL;
		DBG_LOG(val.code);
		return val;
	}

	conf_db_get(conf, txn, C_TPL, key1_name, CONF_DEFAULT_ID + 1,
	            CONF_DEFAULT_ID[0], &val);
	switch (val.code) {
	default:
		CONF_LOG(LOG_ERR, "failed to read default '%s/%s' (%s)",
		         &C_TPL[1], &key1_name[1], knot_strerror(val.code));
		// FALLTHROUGH
	case KNOT_EOK:
	case KNOT_ENOENT:
	case KNOT_YP_EINVAL_ID:
		break;
	}

	return val;
}

bool conf_rawid_exists_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0_name,
	const uint8_t *id,
	size_t id_len)
{
	if (key0_name == NULL || id == NULL) {
		DBG_LOG(KNOT_EINVAL);
		return false;
	}

	int ret = conf_db_get(conf, txn, key0_name, NULL, id, id_len, NULL);
	switch (ret) {
	case KNOT_EOK:
		return true;
	default:
		CONF_LOG(LOG_ERR, "failed to check '%s' for identifier (%s)",
		         key0_name + 1, knot_strerror(ret));
		// FALLTHROUGH
	case KNOT_ENOENT:
	case KNOT_YP_EINVAL_ID:
		return false;
	}
}

bool conf_id_exists_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0_name,
	conf_val_t *id)
{
	if (key0_name == NULL || id == NULL || id->code != KNOT_EOK) {
		DBG_LOG(KNOT_EINVAL);
		return false;
	}

	conf_val(id);

	int ret = conf_db_get(conf, txn, key0_name, NULL, id->data, id->len, NULL);
	switch (ret) {
	case KNOT_EOK:
		return true;
	default:
		CONF_LOG(LOG_ERR, "failed to check '%s' for identifier (%s)",
		         key0_name + 1, knot_strerror(ret));
		// FALLTHROUGH
	case KNOT_ENOENT:
	case KNOT_YP_EINVAL_ID:
		return false;
	}
}

size_t conf_id_count_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0_name)
{
	size_t count = 0;

	for (conf_iter_t iter = conf_iter_txn(conf, txn, key0_name);
	     iter.code == KNOT_EOK; conf_iter_next(conf, &iter)) {
		count++;
	}

	return count;
}

conf_iter_t conf_iter_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0_name)
{
	conf_iter_t iter = { NULL };

	(void)conf_db_iter_begin(conf, txn, key0_name, &iter);
	switch (iter.code) {
	default:
		CONF_LOG(LOG_ERR, "failed to iterate through '%s' (%s)",
		          key0_name + 1, knot_strerror(iter.code));
		// FALLTHROUGH
	case KNOT_EOK:
	case KNOT_ENOENT:
		return iter;
	}
}

void conf_iter_next(
	conf_t *conf,
	conf_iter_t *iter)
{
	(void)conf_db_iter_next(conf, iter);
	switch (iter->code) {
	default:
		CONF_LOG(LOG_ERR, "failed to read next item (%s)",
		          knot_strerror(iter->code));
		// FALLTHROUGH
	case KNOT_EOK:
	case KNOT_EOF:
		return;
	}
}

conf_val_t conf_iter_id(
	conf_t *conf,
	conf_iter_t *iter)
{
	conf_val_t val = { NULL };

	val.code = conf_db_iter_id(conf, iter, &val.blob, &val.blob_len);
	switch (val.code) {
	default:
		CONF_LOG(LOG_ERR, "failed to read identifier (%s)",
		          knot_strerror(val.code));
		// FALLTHROUGH
	case KNOT_EOK:
		val.item = iter->item;
		return val;
	}
}

void conf_iter_finish(
	conf_t *conf,
	conf_iter_t *iter)
{
	conf_db_iter_finish(conf, iter);
}

size_t conf_val_count(
	conf_val_t *val)
{
	if (val == NULL || val->code != KNOT_EOK) {
		return 0;
	}

	if (!(val->item->flags & YP_FMULTI)) {
		return 1;
	}

	size_t count = 0;
	conf_val(val);
	while (val->code == KNOT_EOK) {
		count++;
		conf_val_next(val);
	}
	if (val->code != KNOT_EOF) {
		return 0;
	}

	// Reset to the initial state.
	conf_val(val);

	return count;
}

void conf_val(
	conf_val_t *val)
{
	assert(val != NULL);
	assert(val->code == KNOT_EOK || val->code == KNOT_EOF);

	if (val->item->flags & YP_FMULTI) {
		// Check if already called and not at the end.
		if (val->data != NULL && val->code != KNOT_EOF) {
			return;
		}
		// Otherwise set to the first value.
		conf_val_reset(val);
	} else {
		// Check for empty data.
		if (val->blob_len == 0) {
			val->data = NULL;
			val->len = 0;
			val->code = KNOT_EOK;
			return;
		} else {
			assert(val->blob != NULL);
			val->data = val->blob;
			val->len = val->blob_len;
			val->code = KNOT_EOK;
		}
	}
}

void conf_val_next(
	conf_val_t *val)
{
	assert(val != NULL);
	assert(val->code == KNOT_EOK);
	assert(val->item->flags & YP_FMULTI);

	// Check for the 'zero' call.
	if (val->data == NULL) {
		conf_val(val);
		return;
	}

	if (val->data + val->len < val->blob + val->blob_len) {
		wire_ctx_t ctx = wire_ctx_init_const(val->blob, val->blob_len);
		size_t offset = val->data + val->len - val->blob;
		wire_ctx_skip(&ctx, offset);
		uint16_t len = wire_ctx_read_u16(&ctx);
		assert(ctx.error == KNOT_EOK);

		val->data = ctx.position;
		val->len = len;
		val->code = KNOT_EOK;
	} else {
		val->data = NULL;
		val->len = 0;
		val->code = KNOT_EOF;
	}
}

void conf_val_reset(conf_val_t *val)
{
	assert(val != NULL);
	assert(val->code == KNOT_EOK || val->code == KNOT_EOF);
	assert(val->item->flags & YP_FMULTI);

	assert(val->blob != NULL);
	wire_ctx_t ctx = wire_ctx_init_const(val->blob, val->blob_len);
	uint16_t len = wire_ctx_read_u16(&ctx);
	assert(ctx.error == KNOT_EOK);

	val->data = ctx.position;
	val->len = len;
	val->code = KNOT_EOK;
}

bool conf_val_equal(
	conf_val_t *val1,
	conf_val_t *val2)
{
	if (val1->blob_len == val2->blob_len &&
	    memcmp(val1->blob, val2->blob, val1->blob_len) == 0) {
		return true;
	}

	return false;
}

int64_t conf_int(
	conf_val_t *val)
{
	assert(val != NULL && val->item != NULL);
	assert(val->item->type == YP_TINT ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TINT));

	if (val->code == KNOT_EOK) {
		conf_val(val);
		return yp_int(val->data);
	} else {
		return val->item->var.i.dflt;
	}
}

bool conf_bool(
	conf_val_t *val)
{
	assert(val != NULL && val->item != NULL);
	assert(val->item->type == YP_TBOOL ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TBOOL));

	if (val->code == KNOT_EOK) {
		conf_val(val);
		return yp_bool(val->data);
	} else {
		return val->item->var.b.dflt;
	}
}

unsigned conf_opt(
	conf_val_t *val)
{
	assert(val != NULL && val->item != NULL);
	assert(val->item->type == YP_TOPT ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TOPT));

	if (val->code == KNOT_EOK) {
		conf_val(val);
		return yp_opt(val->data);
	} else {
		return val->item->var.o.dflt;
	}
}

const char* conf_str(
	conf_val_t *val)
{
	assert(val != NULL && val->item != NULL);
	assert(val->item->type == YP_TSTR ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TSTR));

	if (val->code == KNOT_EOK) {
		conf_val(val);
		return yp_str(val->data);
	} else {
		return val->item->var.s.dflt;
	}
}

const knot_dname_t* conf_dname(
	conf_val_t *val)
{
	assert(val != NULL && val->item != NULL);
	assert(val->item->type == YP_TDNAME ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TDNAME));

	if (val->code == KNOT_EOK) {
		conf_val(val);
		return yp_dname(val->data);
	} else {
		return (const knot_dname_t *)val->item->var.d.dflt;
	}
}

const uint8_t* conf_bin(
	conf_val_t *val,
	size_t *len)
{
	assert(val != NULL && val->item != NULL && len != NULL);
	assert(val->item->type == YP_THEX || val->item->type == YP_TB64 ||
	       (val->item->type == YP_TREF &&
	        (val->item->var.r.ref->var.g.id->type == YP_THEX ||
	         val->item->var.r.ref->var.g.id->type == YP_TB64)));

	if (val->code == KNOT_EOK) {
		conf_val(val);
		*len = yp_bin_len(val->data);
		return yp_bin(val->data);
	} else {
		*len = val->item->var.d.dflt_len;
		return val->item->var.d.dflt;
	}
}

const uint8_t* conf_data(
	conf_val_t *val,
	size_t *len)
{
	assert(val != NULL && val->item != NULL);
	assert(val->item->type == YP_TDATA ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TDATA));

	if (val->code == KNOT_EOK) {
		conf_val(val);
		*len = val->len;
		return val->data;
	} else {
		*len = val->item->var.d.dflt_len;
		return val->item->var.d.dflt;
	}
}

struct sockaddr_storage conf_addr(
	conf_val_t *val,
	const char *sock_base_dir)
{
	assert(val != NULL && val->item != NULL);
	assert(val->item->type == YP_TADDR ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TADDR));

	struct sockaddr_storage out = { AF_UNSPEC };

	if (val->code == KNOT_EOK) {
		bool no_port;
		conf_val(val);
		assert(val->data);
		out = yp_addr(val->data, &no_port);

		if (out.ss_family == AF_UNIX) {
			// val->data[0] is socket type identifier!
			if (val->data[1] != '/' && sock_base_dir != NULL) {
				char *tmp = sprintf_alloc("%s/%s", sock_base_dir,
				                          val->data + 1);
				val->code = sockaddr_set(&out, AF_UNIX, tmp, 0);
				free(tmp);
			}
		} else if (no_port) {
			sockaddr_port_set(&out, val->item->var.a.dflt_port);
		}
	} else {
		const char *dflt_socket = val->item->var.a.dflt_socket;
		if (dflt_socket != NULL) {
			if (dflt_socket[0] == '/' || sock_base_dir == NULL) {
				val->code = sockaddr_set(&out, AF_UNIX,
				                         dflt_socket, 0);
			} else {
				char *tmp = sprintf_alloc("%s/%s", sock_base_dir,
				                          dflt_socket);
				val->code = sockaddr_set(&out, AF_UNIX, tmp, 0);
				free(tmp);
			}
		}
	}

	return out;
}

bool conf_addr_match(
	conf_val_t *match,
	const struct sockaddr_storage *addr)
{
	if (match == NULL || addr == NULL) {
		return false;
	}

	while (match->code == KNOT_EOK) {
		struct sockaddr_storage maddr = conf_addr(match, NULL);
		if (sockaddr_cmp(&maddr, addr, true) == 0) {
			return true;
		}

		conf_val_next(match);
	}

	return false;
}

struct sockaddr_storage conf_addr_range(
	conf_val_t *val,
	struct sockaddr_storage *max_ss,
	int *prefix_len)
{
	assert(val != NULL && val->item != NULL && max_ss != NULL &&
	       prefix_len != NULL);
	assert(val->item->type == YP_TNET ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TNET));

	struct sockaddr_storage out = { AF_UNSPEC };

	if (val->code == KNOT_EOK) {
		conf_val(val);
		assert(val->data);
		out = yp_addr_noport(val->data);
		// addr_type, addr, format, formatted_data (port| addr| empty).
		const uint8_t *format = val->data + sizeof(uint8_t) +
		                        ((out.ss_family == AF_INET) ?
		                        IPV4_PREFIXLEN / 8 : IPV6_PREFIXLEN / 8);
		// See addr_range_to_bin.
		switch (*format) {
		case 1:
			max_ss->ss_family = AF_UNSPEC;
			*prefix_len = yp_int(format + sizeof(uint8_t));
			break;
		case 2:
			*max_ss = yp_addr_noport(format + sizeof(uint8_t));
			*prefix_len = -1;
			break;
		default:
			max_ss->ss_family = AF_UNSPEC;
			*prefix_len = -1;
			break;
		}
	} else {
		max_ss->ss_family = AF_UNSPEC;
		*prefix_len = -1;
	}

	return out;
}

bool conf_addr_range_match(
	conf_val_t *range,
	const struct sockaddr_storage *addr)
{
	if (range == NULL || addr == NULL) {
		return false;
	}

	while (range->code == KNOT_EOK) {
		int mask;
		struct sockaddr_storage min, max;

		min = conf_addr_range(range, &max, &mask);
		if (max.ss_family == AF_UNSPEC) {
			if (sockaddr_net_match(addr, &min, mask)) {
				return true;
			}
		} else {
			if (sockaddr_range_match(addr, &min, &max)) {
				return true;
			}
		}

		conf_val_next(range);
	}

	return false;
}

char* conf_abs_path(
	conf_val_t *val,
	const char *base_dir)
{
	const char *path = conf_str(val);
	if (path == NULL) {
		return NULL;
	} else if (path[0] == '/') {
		return strdup(path);
	} else {
		char *abs_path;
		if (base_dir == NULL) {
			char *cwd = realpath("./", NULL);
			abs_path = sprintf_alloc("%s/%s", cwd, path);
			free(cwd);
		} else {
			abs_path = sprintf_alloc("%s/%s", base_dir, path);
		}
		return abs_path;
	}
}

conf_mod_id_t* conf_mod_id(
	conf_val_t *val)
{
	assert(val != NULL && val->item != NULL);
	assert(val->item->type == YP_TDATA ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TDATA));

	conf_mod_id_t *mod_id = NULL;

	if (val->code == KNOT_EOK) {
		conf_val(val);
		assert(val->data);

		mod_id = malloc(sizeof(conf_mod_id_t));
		if (mod_id == NULL) {
			return NULL;
		}

		// Set module name in yp_name_t format + add zero termination.
		size_t name_len = 1 + val->data[0];
		mod_id->name = malloc(name_len + 1);
		if (mod_id->name == NULL) {
			free(mod_id);
			return NULL;
		}
		memcpy(mod_id->name, val->data, name_len);
		mod_id->name[name_len] = '\0';

		// Set module identifier.
		mod_id->len = val->len - name_len;
		mod_id->data = malloc(mod_id->len);
		if (mod_id->data == NULL) {
			free(mod_id->name);
			free(mod_id);
			return NULL;
		}
		memcpy(mod_id->data, val->data + name_len, mod_id->len);
	}

	return mod_id;
}

void conf_free_mod_id(
	conf_mod_id_t *mod_id)
{
	if (mod_id == NULL) {
		return;
	}

	free(mod_id->name);
	free(mod_id->data);
	free(mod_id);
}

static int get_index(
	const char **start,
	const char *end,
	unsigned *index1,
	unsigned *index2)
{
	char c, *p;
	if (sscanf(*start, "[%u%c", index1, &c) != 2) {
		return KNOT_EINVAL;
	}
	switch (c) {
	case '-':
		p = strchr(*start, '-') + 1;
		if (end - p < 2 || index2 == NULL ||
		    sscanf(p, "%u%c", index2, &c) != 2 || c != ']') {
			return KNOT_EINVAL;
		}
		break;
	case ']':
		if (index2 != NULL) {
			*index2 = *index1;
		}
		break;
	default:
		return KNOT_EINVAL;
	}

	*start = strchr(*start, ']') + 1;
	return ((*index1 < 256 && (index2 == NULL || *index2 < 256)
	         && end - *start >= 0 && (index2 == NULL || *index2 >= *index1))
	        ? KNOT_EOK : KNOT_EINVAL);
}

static void replace_slashes(
	char *name,
	bool remove_dot)
{
	// Replace possible slashes with underscores.
	char *ch;
	for (ch = name; *ch != '\0'; ch++) {
		if (*ch == '/') {
			*ch = '_';
		}
	}

	// Remove trailing dot.
	if (remove_dot && ch > name) {
		assert(*(ch - 1) == '.');
		*(ch - 1) = '\0';
	}
}

static int str_char(
	const knot_dname_t *zone,
	char *buff,
	size_t buff_len,
	unsigned index1,
	unsigned index2)
{
	assert(buff);

	if (knot_dname_to_str(buff, zone, buff_len) == NULL) {
		return KNOT_EINVAL;
	}

	size_t zone_len = strlen(buff);
	assert(zone_len > 0);

	// Get the block length.
	size_t len = index2 - index1 + 1;

	// Check for out of scope block.
	if (index1 >= zone_len) {
		buff[0] = '\0';
		return KNOT_EOK;
	}
	// Check for partial block.
	if (index2 >= zone_len) {
		len = zone_len - index1;
	}

	// Copy the block.
	memmove(buff, buff + index1, len);
	buff[len] = '\0';

	// Replace possible slashes with underscores.
	replace_slashes(buff, false);

	return KNOT_EOK;
}

static int str_zone(
	const knot_dname_t *zone,
	char *buff,
	size_t buff_len)
{
	assert(buff);

	if (knot_dname_to_str(buff, zone, buff_len) == NULL) {
		return KNOT_EINVAL;
	}

	// Replace possible slashes with underscores.
	replace_slashes(buff, true);

	return KNOT_EOK;
}

static int str_label(
	const knot_dname_t *zone,
	char *buff,
	size_t buff_len,
	size_t right_index)
{
	size_t labels = knot_dname_labels(zone, NULL);

	// Check for root label of the root zone.
	if (labels == 0 && right_index == 0) {
		return str_zone(zone, buff, buff_len);
	// Check for labels error or for an exceeded index.
	} else if (labels < 1 || labels <= right_index) {
		buff[0] = '\0';
		return KNOT_EOK;
	}

	// ~ Label length + label + root label.
	knot_dname_t label[1 + KNOT_DNAME_MAXLABELLEN + 1];

	// Compute the index from the left.
	assert(labels > right_index);
	size_t index = labels - right_index - 1;

	// Create a dname from the single label.
	size_t prefix_len = knot_dname_prefixlen(zone, index, NULL);
	size_t label_len = *(zone + prefix_len);
	memcpy(label, zone + prefix_len, 1 + label_len);
	label[1 + label_len] = '\0';

	return str_zone(label, buff, buff_len);
}

static char* get_filename(
	conf_t *conf,
	knot_db_txn_t *txn,
	const knot_dname_t *zone,
	const char *name)
{
	assert(name);

	const char *end = name + strlen(name);
	char out[1024] = "";

	do {
		// Search for a formatter.
		const char *pos = strchr(name, '%');

		// If no formatter, copy the rest of the name.
		if (pos == NULL) {
			if (strlcat(out, name, sizeof(out)) >= sizeof(out)) {
				CONF_LOG_ZONE(LOG_WARNING, zone, "too long zonefile name");
				return NULL;
			}
			break;
		}

		// Copy constant block.
		char *block = strndup(name, pos - name);
		if (block == NULL ||
		    strlcat(out, block, sizeof(out)) >= sizeof(out)) {
			CONF_LOG_ZONE(LOG_WARNING, zone, "too long zonefile name");
			free(block);
			return NULL;
		}
		free(block);

		// Move name pointer behind the formatter.
		name = pos + 2;

		char buff[512] = "";
		unsigned idx1, idx2;
		bool failed = false;

		const char type = *(pos + 1);
		switch (type) {
		case '%':
			strlcat(buff, "%", sizeof(buff));
			break;
		case 'c':
			if (get_index(&name, end, &idx1, &idx2) != KNOT_EOK ||
			    str_char(zone, buff, sizeof(buff), idx1, idx2) != KNOT_EOK) {
				failed = true;
			}
			break;
		case 'l':
			if (get_index(&name, end, &idx1, NULL) != KNOT_EOK ||
			    str_label(zone, buff, sizeof(buff), idx1) != KNOT_EOK) {
				failed = true;
			}
			break;
		case 's':
			if (str_zone(zone, buff, sizeof(buff)) != KNOT_EOK) {
				failed = true;
			}
			break;
		case '\0':
			CONF_LOG_ZONE(LOG_WARNING, zone, "ignoring missing "
			              "trailing zonefile formatter");
			continue;
		default:
			CONF_LOG_ZONE(LOG_WARNING, zone, "ignoring zonefile "
			              "formatter '%%%c'", type);
			continue;
		}

		if (failed) {
			CONF_LOG_ZONE(LOG_WARNING, zone, "failed to process "
			              "zonefile formatter '%%%c'", type);
			return NULL;
		}

		if (strlcat(out, buff, sizeof(out)) >= sizeof(out)) {
			CONF_LOG_ZONE(LOG_WARNING, zone, "too long zonefile name");
			return NULL;
		}
	} while (name < end);

	// Use storage prefix if not absolute path.
	if (out[0] == '/') {
		return strdup(out);
	} else {
		conf_val_t val = conf_zone_get_txn(conf, txn, C_STORAGE, zone);
		char *storage = conf_abs_path(&val, NULL);
		if (storage == NULL) {
			return NULL;
		}
		char *abs = sprintf_alloc("%s/%s", storage, out);
		free(storage);
		return abs;
	}
}

char* conf_zonefile_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const knot_dname_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	conf_val_t val = conf_zone_get_txn(conf, txn, C_FILE, zone);
	const char *file = conf_str(&val);

	// Use default zonefile name pattern if not specified.
	if (file == NULL) {
		file = "%s.zone";
	}

	return get_filename(conf, txn, zone, file);
}

inline static bool legacy_db_fallback(
	const yp_name_t *db_type)
{
	return (db_type[1] == C_JOURNAL_DB[1] ||
	        db_type[1] == C_KASP_DB[1] ||
	        db_type[1] == C_TIMER_DB[1]);
	// warning comparing by first letter as every database has different!
}

char* conf_db_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *db_type)
{
	conf_val_t storage_val = conf_get_txn(conf, txn, C_DB, C_STORAGE);
	if (storage_val.code != KNOT_EOK) {
		storage_val = conf_default_get_txn(conf, txn, C_STORAGE);
	}

	conf_val_t db_val = conf_get_txn(conf, txn, C_DB, db_type);
	if (db_val.code != KNOT_EOK && legacy_db_fallback(db_type)) {
		db_val = conf_default_get_txn(conf, txn, db_type);
	}

	char *storage = conf_abs_path(&storage_val, NULL);
	char *dbdir = conf_abs_path(&db_val, storage);
	free(storage);

	return dbdir;
}

conf_val_t conf_db_param_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *param,
	const yp_name_t *legacy_param)
{
	conf_val_t val = conf_get_txn(conf, txn, C_DB, param);
	if (val.code != KNOT_EOK && legacy_param != NULL) {
		val = conf_default_get_txn(conf, txn, legacy_param);
	}

	return val;
}

bool conf_tcp_reuseport_txn(
	conf_t *conf,
	knot_db_txn_t *txn)
{
	conf_val_t val = conf_get_txn(conf, txn, C_SRV, C_TCP_REUSEPORT);
	return conf_bool(&val);
}

bool conf_socket_affinity_txn(
	conf_t *conf,
	knot_db_txn_t *txn)
{
	conf_val_t val = conf_get_txn(conf, txn, C_SRV, C_SOCKET_AFFINITY);
	return conf_bool(&val);
}

size_t conf_udp_threads_txn(
	conf_t *conf,
	knot_db_txn_t *txn)
{
	conf_val_t val = conf_get_txn(conf, txn, C_SRV, C_UDP_WORKERS);
	int64_t workers = conf_int(&val);
	if (workers == YP_NIL) {
		return dt_optimal_size();
	}

	return workers;
}

size_t conf_tcp_threads_txn(
	conf_t *conf,
	knot_db_txn_t *txn)
{
	conf_val_t val = conf_get_txn(conf, txn, C_SRV, C_TCP_WORKERS);
	int64_t workers = conf_int(&val);
	if (workers == YP_NIL) {
		return MAX(dt_optimal_size(), DFLT_TCP_WORKERS_MIN);
	}

	return workers;
}

size_t conf_xdp_threads_txn(
	conf_t *conf,
	knot_db_txn_t *txn)
{
	size_t workers = 0;

	conf_val_t val = conf_get_txn(conf, txn, C_SRV, C_LISTEN_XDP);
	while (val.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&val, NULL);
		conf_xdp_iface_t iface;
		int ret = conf_xdp_iface(&addr, &iface);
		if (ret == KNOT_EOK) {
			workers += iface.queues;
		}
		conf_val_next(&val);
	}

	return workers;
}

size_t conf_bg_threads_txn(
	conf_t *conf,
	knot_db_txn_t *txn)
{
	conf_val_t val = conf_get_txn(conf, txn, C_SRV, C_BG_WORKERS);
	int64_t workers = conf_int(&val);
	if (workers == YP_NIL) {
		return MIN(dt_optimal_size(), DFLT_BG_WORKERS_MAX);
	}

	return workers;
}

size_t conf_tcp_max_clients_txn(
	conf_t *conf,
	knot_db_txn_t *txn)
{
	conf_val_t val = conf_get_txn(conf, txn, C_SRV, C_TCP_MAX_CLIENTS);
	if (val.code != KNOT_EOK) {
		val = conf_get_txn(conf, txn, C_SRV, C_MAX_TCP_CLIENTS);
	}
	int64_t clients = conf_int(&val);
	if (clients == YP_NIL) {
		static size_t permval = 0;
		if (permval == 0) {
			struct rlimit numfiles;
			if (getrlimit(RLIMIT_NOFILE, &numfiles) == 0) {
				permval = (size_t)numfiles.rlim_cur / 2;
			} else {
				permval = FALLBACK_MAX_TCP_CLIENTS;
			}
		}
		return permval;
	}

	return clients;
}

int conf_user_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	int *uid,
	int *gid)
{
	if (uid == NULL || gid == NULL) {
		return KNOT_EINVAL;
	}

	conf_val_t val = conf_get_txn(conf, txn, C_SRV, C_USER);
	if (val.code == KNOT_EOK) {
		char *user = strdup(conf_str(&val));

		// Search for user:group separator.
		char *sep_pos = strchr(user, ':');
		if (sep_pos != NULL) {
			// Process group name.
			struct group *grp = getgrnam(sep_pos + 1);
			if (grp != NULL) {
				*gid = grp->gr_gid;
			} else {
				CONF_LOG(LOG_ERR, "invalid group name '%s'",
				         sep_pos + 1);
				free(user);
				return KNOT_EINVAL;
			}

			// Cut off group part.
			*sep_pos = '\0';
		} else {
			*gid = getgid();
		}

		// Process user name.
		struct passwd *pwd = getpwnam(user);
		if (pwd != NULL) {
			*uid = pwd->pw_uid;
		} else {
			CONF_LOG(LOG_ERR, "invalid user name '%s'", user);
			free(user);
			return KNOT_EINVAL;
		}

		free(user);
		return KNOT_EOK;
	} else if (val.code == KNOT_ENOENT) {
		*uid = getuid();
		*gid = getgid();
		return KNOT_EOK;
	} else {
		return val.code;
	}
}

conf_remote_t conf_remote_txn(
	conf_t *conf,
	knot_db_txn_t *txn,
	conf_val_t *id,
	size_t index)
{
	assert(id != NULL && id->item != NULL);
	assert(id->item->type == YP_TSTR ||
	       (id->item->type == YP_TREF &&
	        id->item->var.r.ref->var.g.id->type == YP_TSTR));

	conf_remote_t out = { { AF_UNSPEC } };

	conf_val_t rundir_val = conf_get_txn(conf, txn, C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&rundir_val, NULL);

	// Get indexed remote address.
	conf_val_t val = conf_id_get_txn(conf, txn, C_RMT, C_ADDR, id);
	for (size_t i = 0; val.code == KNOT_EOK && i < index; i++) {
		if (i == 0) {
			conf_val(&val);
		}
		conf_val_next(&val);
	}
	// Index overflow causes empty socket.
	out.addr = conf_addr(&val, rundir);

	// Get outgoing address if family matches (optional).
	val = conf_id_get_txn(conf, txn, C_RMT, C_VIA, id);
	while (val.code == KNOT_EOK) {
		struct sockaddr_storage via = conf_addr(&val, rundir);
		if (via.ss_family == out.addr.ss_family) {
			out.via = conf_addr(&val, rundir);
			break;
		}
		conf_val_next(&val);
	}

	// Get TSIG key (optional).
	conf_val_t key_id = conf_id_get_txn(conf, txn, C_RMT, C_KEY, id);
	if (key_id.code == KNOT_EOK) {
		out.key.name = (knot_dname_t *)conf_dname(&key_id);

		val = conf_id_get_txn(conf, txn, C_KEY, C_ALG, &key_id);
		out.key.algorithm = conf_opt(&val);

		val = conf_id_get_txn(conf, txn, C_KEY, C_SECRET, &key_id);
		out.key.secret.data = (uint8_t *)conf_bin(&val, &out.key.secret.size);
	}

	free(rundir);

	val = conf_id_get_txn(conf, txn, C_RMT, C_BLOCK_NOTIFY_XFR, id);
	out.block_notify_after_xfr = conf_bool(&val);

	val = conf_id_get_txn(conf, txn, C_RMT, C_NO_EDNS, id);
	out.no_edns = conf_bool(&val);

	return out;
}

int conf_xdp_iface(
	struct sockaddr_storage *addr,
	conf_xdp_iface_t *iface)
{
#ifndef ENABLE_XDP
	return KNOT_ENOTSUP;
#else
	if (addr == NULL || iface == NULL) {
		return KNOT_EINVAL;
	}

	if (addr->ss_family == AF_UNIX) {
		const char *addr_str = ((struct sockaddr_un *)addr)->sun_path;
		strlcpy(iface->name, addr_str, sizeof(iface->name));

		const char *port = strchr(addr_str, '@');
		if (port != NULL) {
			iface->name[port - addr_str] = '\0';
			int ret = str_to_u16(port + 1, &iface->port);
			if (ret != KNOT_EOK) {
				return ret;
			} else if (iface->port == 0) {
				return KNOT_EINVAL;
			}
		} else {
			iface->port = 53;
		}
	} else {
		int ret = knot_eth_name_from_addr(addr, iface->name, sizeof(iface->name));
		if (ret != KNOT_EOK) {
			return ret;
		}
		ret = sockaddr_port(addr);
		if (ret < 1) {
			return KNOT_EINVAL;
		}
		iface->port = ret;
	}

	int queues = knot_eth_queues(iface->name);
	if (queues <= 0) {
		assert(queues != 0);
		return queues;
	}
	iface->queues = queues;

	return KNOT_EOK;
#endif
}
