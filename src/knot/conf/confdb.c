/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "knot/conf/confdb.h"
#include "libknot/errcode.h"
#include "libknot/yparser/yptrafo.h"

typedef enum {
	KEY0_ROOT    =   0,
	KEY1_ITEMS   =   0,
	KEY1_ID      =   1,
	KEY1_FIRST   =   2,
	KEY1_LAST    = 200,
	KEY1_VERSION = 255
} db_code_t;

typedef enum {
	KEY0_POS = 0,
	KEY1_POS = 1,
	NAME_POS = 2
} db_code_pos_t;

typedef enum {
	DB_GET,
	DB_SET,
	DB_DEL
} db_action_t;

static int db_check_version(
	conf_t *conf,
	namedb_txn_t *txn)
{
	uint8_t k[2] = { KEY0_ROOT, KEY1_VERSION };
	namedb_val_t key = { k, sizeof(k) };
	namedb_val_t data;

	// Get conf-DB version.
	int ret = conf->api->find(txn, &key, &data, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Check conf-DB version.
	if (data.len != 1 || ((uint8_t *)data.data)[0] != CONF_DB_VERSION) {
		return KNOT_CONF_EVERSION;
	}

	return KNOT_EOK;
}

static int db_check(
	conf_t *conf,
	namedb_txn_t *txn)
{
	int ret = conf->api->count(txn);
	if (ret == 0) { // Empty DB.
		return KNOT_CONF_EMPTY;
	} else if (ret > 0) { // Check existing DB.
		return db_check_version(conf, txn);
	} else { // DB error.
		return ret;
	}
}

int conf_db_init(
	conf_t *conf,
	namedb_txn_t *txn)
{
	if (conf == NULL || txn == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t k[2] = { KEY0_ROOT, KEY1_VERSION };
	namedb_val_t key = { k, sizeof(k) };

	int ret = conf->api->count(txn);
	if (ret == 0) { // Initialize empty DB with DB version.
		uint8_t d[1] = { CONF_DB_VERSION };
		namedb_val_t data = { d, sizeof(d) };
		return conf->api->insert(txn, &key, &data, 0);
	} else if (ret > 0) { // Check existing DB.
		return db_check(conf, txn);
	} else { // DB error.
		return ret;
	}
}

static int db_code(
	conf_t *conf,
	namedb_txn_t *txn,
	uint8_t section_code,
	const yp_name_t *name,
	db_action_t action,
	uint8_t *code)
{
	if (name == NULL) {
		return KNOT_EINVAL;
	}

	namedb_val_t key;
	uint8_t k[CONF_MIN_KEY_LEN + YP_MAX_ITEM_NAME_LEN];
	k[KEY0_POS] = section_code;
	k[KEY1_POS] = KEY1_ITEMS;
	memcpy(k + NAME_POS, name + 1, name[0]);
	key.data = k;
	key.len = CONF_MIN_KEY_LEN + name[0];

	// Check if the item is already registered.
	namedb_val_t data;
	int ret = conf->api->find(txn, &key, &data, 0);
	switch (ret) {
	case KNOT_EOK:
		if (action == DB_DEL) {
			return conf->api->del(txn, &key);
		}
		if (code != NULL) {
			*code = ((uint8_t *)data.data)[0];
		}
		return KNOT_EOK;
	case KNOT_ENOENT:
		if (action != DB_SET) {
			return KNOT_ENOENT;
		}
		break;
	default:
		return ret;
	}

	// Reduce the key to common prefix only.
	key.len = CONF_MIN_KEY_LEN;

	bool codes[KEY1_LAST + 1] = { false };

	// Find all used item codes.
	namedb_iter_t *it = conf->api->iter_begin(txn, NAMEDB_NOOP);
	it = conf->api->iter_seek(it, &key, NAMEDB_GEQ);
	while (it != NULL) {
		namedb_val_t iter_key;
		ret = conf->api->iter_key(it, &iter_key);
		if (ret != KNOT_EOK) {
			conf->api->iter_finish(it);
			return ret;
		}
		uint8_t *key_data = (uint8_t *)iter_key.data;

		// Check for database prefix end.
		if (key_data[KEY0_POS] != k[KEY0_POS] ||
		    key_data[KEY1_POS] != k[KEY1_POS]) {
			break;
		}

		namedb_val_t iter_val;
		ret = conf->api->iter_val(it, &iter_val);
		if (ret != KNOT_EOK) {
			conf->api->iter_finish(it);
			return ret;
		}
		uint8_t code = ((uint8_t *)iter_val.data)[0];
		codes[code] = true;

		it = conf->api->iter_next(it);
	}
	conf->api->iter_finish(it);

	// Find the smallest unused item code.
	uint8_t new_code = KEY1_FIRST;
	while (codes[new_code]) {
		new_code++;
		if (new_code > KEY1_LAST) {
			return KNOT_ESPACE;
		}
	}

	// Restore the full key.
	key.len = CONF_MIN_KEY_LEN + name[0];

	// Fill the data with a new code.
	data.data = &new_code;
	data.len = sizeof(new_code);

	// Register new item code.
	ret = conf->api->insert(txn, &key, &data, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (code != NULL) {
		*code = new_code;
	}

	return KNOT_EOK;
}

static uint8_t *find_data(
	const namedb_val_t *value,
	const namedb_val_t *current)
{
	wire_ctx_t ctx = wire_ctx_init_const(current->data, current->len);

	// Loop over the data array. Each item has 2B length prefix.
	while (wire_ctx_available(&ctx) > 0) {
		uint16_t len = wire_ctx_read_u16(&ctx);
		assert(ctx.error == KNOT_EOK);

		// Check for the same data.
		if (len == value->len &&
		    memcmp(ctx.position, value->data, value->len) == 0) {
			wire_ctx_skip(&ctx, -sizeof(uint16_t));
			assert(ctx.error == KNOT_EOK);
			return ctx.position;
		}
		wire_ctx_skip(&ctx, len);
	}

	assert(ctx.error == KNOT_EOK && wire_ctx_available(&ctx) == 0);

	return NULL;
}

static int db_set(
	conf_t *conf,
	namedb_txn_t *txn,
	namedb_val_t *key,
	namedb_val_t *data,
	bool multi)
{
	if (!multi) {
		if (data->len > CONF_MAX_DATA_LEN) {
			return KNOT_ERANGE;
		}

		// Insert new (overwrite old) data.
		return conf->api->insert(txn, key, data, 0);
	}

	namedb_val_t d;

	if (data->len > UINT16_MAX) {
		return KNOT_ERANGE;
	}

	int ret = conf->api->find(txn, key, &d, 0);
	if (ret == KNOT_ENOENT) {
		d.len = 0;
	} else if (ret == KNOT_EOK) {
		// Check for duplicate data.
		if (find_data(data, &d) != NULL) {
			return KNOT_EOK;
		}
	} else {
		return ret;
	}

	// Prepare buffer for all data.
	size_t new_len = d.len + sizeof(uint16_t) + data->len;
	if (new_len > CONF_MAX_DATA_LEN) {
		return KNOT_ESPACE;
	}

	uint8_t *new_data = malloc(new_len);
	if (new_data == NULL) {
		return KNOT_ENOMEM;
	}

	wire_ctx_t ctx = wire_ctx_init(new_data, new_len);

	// Copy current data array.
	wire_ctx_write(&ctx, d.data, d.len);
	// Copy length prefix for the new data item.
	wire_ctx_write_u16(&ctx, data->len);
	// Copy the new data item.
	wire_ctx_write(&ctx, data->data, data->len);

	assert(ctx.error == KNOT_EOK && wire_ctx_available(&ctx) == 0);

	d.data = new_data;
	d.len = new_len;

	// Insert new (or append) data.
	ret = conf->api->insert(txn, key, &d, 0);

	free(new_data);

	return ret;
}

int conf_db_set(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0,
	const yp_name_t *key1,
	const uint8_t *id,
	size_t id_len,
	const uint8_t *data,
	size_t data_len)
{
	if (conf == NULL || txn == NULL || key0 == NULL ||
	    (id == NULL && id_len > 0) || (data == NULL && data_len > 0)) {
		return KNOT_EINVAL;
	}

	// Check for valid keys.
	const yp_item_t *item = yp_scheme_find(key1 != NULL ? key1 : key0,
	                                       key1 != NULL ? key0 : NULL,
	                                       conf->scheme);
	if (item == NULL) {
		return KNOT_YP_EINVAL_ITEM;
	}

	// Ignore alone key0 insertion.
	if (key1 == NULL && id_len == 0) {
		return KNOT_EOK;
	}

	// Ignore group id as a key1.
	if (item->parent != NULL && (item->parent->flags & YP_FMULTI) != 0 &&
	    item->parent->var.g.id == item) {
		key1 = NULL;
	}

	uint8_t k[CONF_MAX_KEY_LEN] = { 0 };
	namedb_val_t key = { k, CONF_MIN_KEY_LEN };

	// Set key0 code.
	int ret = db_code(conf, txn, KEY0_ROOT, key0, DB_SET, &k[KEY0_POS]);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Set id part.
	if (id_len > 0) {
		if (id_len > YP_MAX_ID_LEN) {
			return KNOT_YP_EINVAL_ID;
		}
		memcpy(k + CONF_MIN_KEY_LEN, id, id_len);
		key.len += id_len;

		k[KEY1_POS] = KEY1_ID;
		namedb_val_t val = { NULL };

		// Insert id.
		if (key1 == NULL) {
			ret = conf->api->find(txn, &key, &val, 0);
			if (ret == KNOT_EOK) {
				return KNOT_CONF_EREDEFINE;
			}
			ret = db_set(conf, txn, &key, &val, false);
			if (ret != KNOT_EOK) {
				return ret;
			}
		// Check for existing id.
		} else {
			ret = conf->api->find(txn, &key, &val, 0);
			if (ret != KNOT_EOK) {
				return KNOT_YP_EINVAL_ID;
			}
		}
	}

	// Insert key1 data.
	if (key1 != NULL) {
		// Set key1 code.
		ret = db_code(conf, txn, k[KEY0_POS], key1, DB_SET, &k[KEY1_POS]);
		if (ret != KNOT_EOK) {
			return ret;
		}

		namedb_val_t val = { (uint8_t *)data, data_len };
		ret = db_set(conf, txn, &key, &val, item->flags & YP_FMULTI);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int db_unset(
	conf_t *conf,
	namedb_txn_t *txn,
	namedb_val_t *key,
	namedb_val_t *data,
	bool multi)
{
	// No item data can be zero length.
	if (data->len == 0) {
		return conf->api->del(txn, key);
	}

	namedb_val_t d;

	int ret = conf->api->find(txn, key, &d, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Process singlevalued data.
	if (!multi) {
		if (d.len != data->len ||
		    memcmp((uint8_t *)d.data, data->data, d.len) != 0) {
			return KNOT_ENOENT;
		}
		return conf->api->del(txn, key);
	}

	// Check if the data exists.
	uint8_t *pos = find_data(data, &d);
	if (pos == NULL) {
		return KNOT_ENOENT;
	}

	// Prepare buffer for reduced data.
	size_t total_len = d.len - sizeof(uint16_t) - data->len;
	if (total_len  == 0) {
		return conf->api->del(txn, key);
	}

	uint8_t *new_data = malloc(total_len);
	if (new_data == NULL) {
		return KNOT_ENOMEM;
	}

	size_t new_len = 0;

	// Copy leading data block.
	assert(pos >= (uint8_t *)d.data);
	size_t head_len = pos - (uint8_t *)d.data;
	if (head_len > 0) {
		memcpy(new_data, d.data, head_len);
		new_len += head_len;
	}

	pos += sizeof(uint16_t) + data->len;

	// Copy trailing data block.
	assert(pos <= (uint8_t *)d.data + d.len);
	size_t tail_len = (uint8_t *)d.data + d.len - pos;
	if (tail_len > 0) {
		memcpy(new_data + new_len, pos, tail_len);
		new_len += tail_len;
	}

	d.data = new_data;
	d.len = new_len;

	// Insert reduced data.
	ret = conf->api->insert(txn, key, &d, 0);

	free(new_data);

	return ret;
}

int conf_db_unset(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0,
	const yp_name_t *key1,
	const uint8_t *id,
	size_t id_len,
	const uint8_t *data,
	size_t data_len,
	bool delete_key1)
{
	if (conf == NULL || txn == NULL || key0 == NULL ||
	    (id == NULL && id_len > 0) || (data == NULL && data_len > 0)) {
		return KNOT_EINVAL;
	}

	// Check for valid keys.
	const yp_item_t *item = yp_scheme_find(key1 != NULL ? key1 : key0,
	                                       key1 != NULL ? key0 : NULL,
	                                       conf->scheme);
	if (item == NULL) {
		return KNOT_YP_EINVAL_ITEM;
	}

	// Delete the key0.
	if (key1 == NULL && id_len == 0) {
		return db_code(conf, txn, KEY0_ROOT, key0, DB_DEL, NULL);
	}

	// Ignore group id as a key1.
	if (item->parent != NULL && (item->parent->flags & YP_FMULTI) != 0 &&
	    item->parent->var.g.id == item) {
		key1 = NULL;
	}

	uint8_t k[CONF_MAX_KEY_LEN] = { 0 };
	namedb_val_t key = { k, CONF_MIN_KEY_LEN };

	// Set the key0 code.
	int ret = db_code(conf, txn, KEY0_ROOT, key0, DB_GET, &k[KEY0_POS]);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Set the id part.
	if (id_len > 0) {
		if (id_len > YP_MAX_ID_LEN) {
			return KNOT_YP_EINVAL_ID;
		}
		memcpy(k + CONF_MIN_KEY_LEN, id, id_len);
		key.len += id_len;

		k[KEY1_POS] = KEY1_ID;
		namedb_val_t val = { NULL };

		// Delete the id.
		if (key1 == NULL) {
			return conf->api->del(txn, &key);
		// Check for existing id.
		} else {
			ret = conf->api->find(txn, &key, &val, 0);
			if (ret != KNOT_EOK) {
				return KNOT_YP_EINVAL_ID;
			}
		}
	}

	if (key1 != NULL) {
		// Set the key1 code.
		ret = db_code(conf, txn, k[KEY0_POS], key1, DB_GET, &k[KEY1_POS]);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Delete the key1.
		if (data_len == 0 && delete_key1) {
			ret = db_code(conf, txn, k[KEY0_POS], key1, DB_DEL, NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
		// Delete the item data.
		} else {
			namedb_val_t val = { (uint8_t *)data, data_len };
			ret = db_unset(conf, txn, &key, &val, item->flags & YP_FMULTI);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

int conf_db_get(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0,
	const yp_name_t *key1,
	const uint8_t *id,
	size_t id_len,
	conf_val_t *data)
{
	conf_val_t out = { NULL };

	if (conf == NULL || txn == NULL || key0 == NULL ||
	    (id == NULL && id_len > 0)) {
		out.code = KNOT_EINVAL;
		goto get_error;
	}

	// Check for valid keys.
	out.item = yp_scheme_find(key1 != NULL ? key1 : key0,
	                          key1 != NULL ? key0 : NULL,
	                          conf->scheme);
	if (out.item == NULL) {
		out.code = KNOT_YP_EINVAL_ITEM;
		goto get_error;
	}

	// At least key1 or id must be specified.
	if (key1 == NULL && id_len == 0) {
		out.code = KNOT_EINVAL;
		goto get_error;
	}

	// Ignore group id as a key1.
	if (out.item->parent != NULL && (out.item->parent->flags & YP_FMULTI) != 0 &&
	    out.item->parent->var.g.id == out.item) {
		key1 = NULL;
	}

	uint8_t k[CONF_MAX_KEY_LEN] = { 0 };
	namedb_val_t key = { k, CONF_MIN_KEY_LEN };
	namedb_val_t val = { NULL };

	// Set the key0 code.
	out.code = db_code(conf, txn, KEY0_ROOT, key0, DB_GET, &k[KEY0_POS]);
	if (out.code != KNOT_EOK) {
		goto get_error;
	}

	// Set the id part.
	if (id_len > 0) {
		if (id_len > YP_MAX_ID_LEN) {
			out.code = KNOT_YP_EINVAL_ID;
			goto get_error;
		}
		memcpy(k + CONF_MIN_KEY_LEN, id, id_len);
		key.len += id_len;

		k[KEY1_POS] = KEY1_ID;

		// Check for existing id.
		out.code = conf->api->find(txn, &key, &val, 0);
		if (out.code != KNOT_EOK) {
			out.code = KNOT_YP_EINVAL_ID;
			goto get_error;
		}
	}

	// Set the key1 code.
	if (key1 != NULL) {
		out.code = db_code(conf, txn, k[KEY0_POS], key1, DB_GET, &k[KEY1_POS]);
		if (out.code != KNOT_EOK) {
			goto get_error;
		}
	}

	// Get the data.
	out.code = conf->api->find(txn, &key, &val, 0);
	if (out.code == KNOT_EOK) {
		out.blob = val.data;
		out.blob_len = val.len;
	}
get_error:
	// Set the output.
	if (data != NULL) {
		*data = out;
	}

	return out.code;
}

static int check_iter(
	conf_t *conf,
	conf_iter_t *iter)
{
	namedb_val_t key;

	// Get the current key.
	int ret = conf->api->iter_key(iter->iter, &key);
	if (ret != KNOT_EOK) {
		return KNOT_ENOENT;
	}
	uint8_t *key_data = (uint8_t *)key.data;

	// Check for key overflow.
	if (key_data[KEY0_POS] != iter->key0_code || key_data[KEY1_POS] != KEY1_ID) {
		return KNOT_EOF;
	}

	return KNOT_EOK;
}

int conf_db_iter_begin(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0,
	conf_iter_t *iter)
{
	conf_iter_t out = { NULL };

	if (conf == NULL || txn == NULL || key0 == NULL || iter == NULL) {
		out.code = KNOT_EINVAL;
		goto iter_begin_error;
	}

	// Look-up group id item in the scheme.
	const yp_item_t *grp = yp_scheme_find(key0, NULL, conf->scheme);
	if (grp == NULL) {
		out.code = KNOT_YP_EINVAL_ITEM;
		goto iter_begin_error;
	}
	if (grp->type != YP_TGRP || (grp->flags & YP_FMULTI) == 0) {
		out.code = KNOT_ENOTSUP;
		goto iter_begin_error;
	}
	out.item = grp->var.g.id;

	// Get key0 code.
	out.code = db_code(conf, txn, KEY0_ROOT, key0, DB_GET, &out.key0_code);
	if (out.code != KNOT_EOK) {
		goto iter_begin_error;
	}

	// Prepare key prefix.
	uint8_t k[2] = { out.key0_code, KEY1_ID };
	namedb_val_t key = { k, sizeof(k) };

	// Get the data.
	out.iter = conf->api->iter_begin(txn, NAMEDB_NOOP);
	out.iter = conf->api->iter_seek(out.iter, &key, NAMEDB_GEQ);

	// Check for no section id.
	out.code = check_iter(conf, &out);
	if (out.code != KNOT_EOK) {
		goto iter_begin_error;
	}

iter_begin_error:
	*iter = out;

	return out.code;
}

int conf_db_iter_next(
	conf_t *conf,
	conf_iter_t *iter)
{
	if (conf == NULL || iter == NULL) {
		return KNOT_EINVAL;
	}

	if (iter->code != KNOT_EOK) {
		return iter->code;
	}
	assert(iter->iter != NULL);

	// Move to the next key-value.
	iter->iter = conf->api->iter_next(iter->iter);
	if (iter->iter == NULL) {
		conf_db_iter_finish(conf, iter);
		iter->code = KNOT_EOF;
		return iter->code;
	}

	// Check for key overflow.
	iter->code = check_iter(conf, iter);
	if (iter->code != KNOT_EOK) {
		conf_db_iter_finish(conf, iter);
		return iter->code;
	}

	return KNOT_EOK;
}

int conf_db_iter_id(
	conf_t *conf,
	conf_iter_t *iter,
	const uint8_t **data,
	size_t *data_len)
{
	if (conf == NULL || iter == NULL || iter->iter == NULL ||
	    data == NULL || data_len == NULL) {
		return KNOT_EINVAL;
	}

	namedb_val_t key;
	int ret = conf->api->iter_key(iter->iter, &key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	*data = (uint8_t *)key.data + CONF_MIN_KEY_LEN;
	*data_len = key.len - CONF_MIN_KEY_LEN;

	return KNOT_EOK;
}

int conf_db_iter_del(
	conf_t *conf,
	conf_iter_t *iter)
{
	if (conf == NULL || iter == NULL || iter->iter == NULL) {
		return KNOT_EINVAL;
	}

	return namedb_lmdb_iter_del(iter->iter);
}

void conf_db_iter_finish(
	conf_t *conf,
	conf_iter_t *iter)
{
	if (conf == NULL || iter == NULL) {
		return;
	}

	if (iter->iter != NULL) {
		conf->api->iter_finish(iter->iter);
		iter->iter = NULL;
	}
}

int conf_db_raw_dump(
	conf_t *conf,
	namedb_txn_t *txn,
	const char *file_name)
{
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	// Use the current config read transaction if not specified.
	if (txn == NULL) {
		txn = &conf->read_txn;
	}

	FILE *fp = stdout;
	if (file_name != NULL) {
		fp = fopen(file_name, "w");
		if (fp == NULL) {
			return KNOT_ERROR;
		}
	}

	int ret = KNOT_EOK;

	namedb_iter_t *it = conf->api->iter_begin(txn, NAMEDB_FIRST);
	while (it != NULL) {
		namedb_val_t key;
		ret = conf->api->iter_key(it, &key);
		if (ret != KNOT_EOK) {
			break;
		}

		namedb_val_t data;
		ret = conf->api->iter_val(it, &data);
		if (ret != KNOT_EOK) {
			break;
		}

		uint8_t *k = (uint8_t *)key.data;
		uint8_t *d = (uint8_t *)data.data;
		if (k[1] == KEY1_ITEMS) {
			fprintf(fp, "[%i][%i]%.*s", k[0], k[1],
			        (int)key.len - 2, k + 2);
			fprintf(fp, ": %u\n", d[0]);
		} else if (k[1] == KEY1_ID) {
			fprintf(fp, "[%i][%i](%zu){", k[0], k[1], key.len - 2);
			for (size_t i = 2; i < key.len; i++) {
				fprintf(fp, "%02x", (uint8_t)k[i]);
			}
			fprintf(fp, "}\n");
		} else {
			fprintf(fp, "[%i][%i]", k[0], k[1]);
			if (key.len > 2) {
				fprintf(fp, "(%zu){", key.len - 2);
				for (size_t i = 2; i < key.len; i++) {
					fprintf(fp, "%02x", (uint8_t)k[i]);
				}
				fprintf(fp, "}");
			}
			fprintf(fp, ": (%zu)<", data.len);
			for (size_t i = 0; i < data.len; i++) {
				fprintf(fp, "%02x", (uint8_t)d[i]);
			}
			fprintf(fp, ">\n");
		}

		it = conf->api->iter_next(it);
	}
	conf->api->iter_finish(it);

	if (file_name != NULL) {
		fclose(fp);
	} else {
		fflush(fp);
	}

	return ret;
}
