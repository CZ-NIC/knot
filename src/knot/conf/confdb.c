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

#define KEY0_POS	0
#define KEY1_POS	1
#define NAME_POS	2

static int conf_db_check(
	conf_t *conf,
	namedb_txn_t *txn)
{
	int ret = conf->api->count(txn);
	if (ret == 0) { // Empty DB.
		return KNOT_CONF_EMPTY;
	} else if (ret > 0) { // Check existing DB.
		uint8_t k[2] = { CONF_CODE_KEY0_ROOT, CONF_CODE_KEY1_VERSION };
		namedb_val_t key = { k, sizeof(k) };
		namedb_val_t data;

		// Get conf-DB version.
		ret = conf->api->find(txn, &key, &data, 0);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Check conf-DB version.
		if (data.len != 1 ||
		    ((uint8_t *)data.data)[0] != CONF_DB_VERSION) {
			return KNOT_CONF_EVERSION;
		}

		return KNOT_EOK;
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

	uint8_t k[2] = { CONF_CODE_KEY0_ROOT, CONF_CODE_KEY1_VERSION };
	namedb_val_t key = { k, sizeof(k) };

	int ret = conf->api->count(txn);
	if (ret == 0) { // Initialize empty DB with DB version.
		uint8_t d[1] = { CONF_DB_VERSION };
		namedb_val_t data = { d, sizeof(d) };
		return conf->api->insert(txn, &key, &data, 0);
	} else if (ret > 0) { // Check existing DB.
		return conf_db_check(conf, txn);
	} else { // DB error.
		return ret;
	}
}

int conf_db_code(
	conf_t *conf,
	namedb_txn_t *txn,
	uint8_t section_code,
	const yp_name_t *name,
	bool read_only,
	uint8_t *db_code)
{
	if (conf == NULL || txn == NULL || name == NULL || db_code == NULL) {
		return KNOT_EINVAL;
	}

	namedb_val_t key;
	uint8_t k[CONF_MIN_KEY_LEN + YP_MAX_ITEM_NAME_LEN];
	k[KEY0_POS] = section_code;
	k[KEY1_POS] = CONF_CODE_KEY1_ITEMS;
	memcpy(k + NAME_POS, name + 1, name[0]);
	key.data = k;
	key.len = CONF_MIN_KEY_LEN + name[0];

	// Check if the item is already registered.
	namedb_val_t data;
	int ret = conf->api->find(txn, &key, &data, 0);
	if (ret == KNOT_EOK) {
		*db_code = ((uint8_t *)data.data)[0];
		return KNOT_EOK;
	} else if (read_only) {
		return KNOT_ENOENT;
	}

	uint8_t new_code = CONF_CODE_KEY1_FIRST;

	// Reduce the key to common prefix only.
	key.len = CONF_MIN_KEY_LEN;

	// Find the smallest unused item code.
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

		// Check the current code if already used.
		if (new_code <= code) {
			if (code == CONF_CODE_KEY1_LAST) {
				conf->api->iter_finish(it);
				return KNOT_ERANGE;
			}
			new_code = code + 1;
		}

		it = conf->api->iter_next(it);
	}
	conf->api->iter_finish(it);

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

	*db_code = new_code;

	return KNOT_EOK;
}

static bool new_data(
	const namedb_val_t *new,
	const namedb_val_t *current)
{
	uint8_t *d = current->data;
	size_t len = 0;

	// Loop over the data array. Each item has 2B prefix.
	while (len < current->len) {
		uint16_t prefix;
		memcpy(&prefix, d + len, sizeof(prefix));
		prefix = le16toh(prefix);
		len += sizeof(prefix);

		// Check for the same data.
		if (prefix == new->len &&
		    memcmp(d + len, new->data, new->len) == 0) {
			return false;
		}
		len += prefix;
	}

	return true;
}

static int db_insert(
	conf_t *conf,
	namedb_txn_t *txn,
	namedb_val_t *key,
	namedb_val_t *data,
	bool multi)
{
	if (multi) {
		namedb_val_t d;

		if (data->len > UINT16_MAX) {
			return KNOT_ERANGE;
		}

		int ret = conf->api->find(txn, key, &d, 0);
		if (ret == KNOT_ENOENT) {
			d.len = 0;
		} else if (ret == KNOT_EOK) {
			// Check for duplicate data.
			if (!new_data(data, &d)) {
				return KNOT_EOK;
			}
		} else {
			return ret;
		}

		// Prepare buffer for all data.
		size_t total_len = d.len + sizeof(uint16_t) + data->len;
		if (total_len > CONF_MAX_DATA_LEN) {
			return KNOT_ESPACE;
		}

		uint8_t *new_data = malloc(total_len);
		if (new_data == NULL) {
			return KNOT_ENOMEM;
		}

		size_t new_len = 0;

		// Copy current data array.
		memcpy(new_data, d.data, d.len);
		new_len += d.len;

		// Copy length prefix for the new data item.
		uint16_t prefix = htole16(data->len);
		memcpy(new_data + new_len, &prefix, sizeof(prefix));
		new_len += sizeof(prefix);

		// Copy the new data item.
		memcpy(new_data + new_len, data->data, data->len);
		new_len += data->len;

		d.data = new_data;
		d.len = new_len;

		// Insert new (or append) data.
		ret = conf->api->insert(txn, key, &d, 0);

		free(new_data);

		return ret;
	} else {
		if (data->len > CONF_MAX_DATA_LEN) {
			return KNOT_ERANGE;
		}

		// Insert new (overwrite old) data.
		return conf->api->insert(txn, key, data, 0);
	}
}

int conf_db_set(
	conf_t *conf,
	namedb_txn_t *txn,
	yp_check_ctx_t *in)
{
	if (conf == NULL || txn == NULL || in == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t k[CONF_MAX_KEY_LEN];
	namedb_val_t key = { k, CONF_MIN_KEY_LEN };

	// Ignore alone key0 insertion.
	if (in->event == YP_EKEY0) {
		return KNOT_EOK;
	}

	// Set key0 code.
	int ret = conf_db_code(conf, txn, CONF_CODE_KEY0_ROOT, in->key0->name,
	                       false, &k[KEY0_POS]);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Set id part.
	if (in->id_len > 0) {
		memcpy(k + CONF_MIN_KEY_LEN, in->id, in->id_len);
		key.len += in->id_len;
	}

	// Insert id.
	if (in->event == YP_EID) {
		k[KEY1_POS] = CONF_CODE_KEY1_ID;
		namedb_val_t val = { NULL };

		// Check for already configured id.
		ret = conf->api->find(txn, &key, &val, 0);
		if (ret == KNOT_EOK) {
			return KNOT_CONF_EREDEFINE;
		}

		return db_insert(conf, txn, &key, &val, false);
	// Insert data.
	} else {
		// Set key1 code.
		ret = conf_db_code(conf, txn, k[KEY0_POS], in->key1->name,
		                   false, &k[KEY1_POS]);
		if (ret != KNOT_EOK) {
			return ret;
		}

		namedb_val_t val = { in->data, in->data_len };
		return db_insert(conf, txn, &key, &val,
		                 in->key1->flags & YP_FMULTI);
	}
}

int conf_db_get(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0,
	const yp_name_t *key1,
	const uint8_t *id,
	size_t id_len,
	conf_val_t *out)
{
	if (conf == NULL || txn == NULL || key0 == NULL) {
		return KNOT_EINVAL;
	}

	// Look-up item in the scheme.
	if (out != NULL) {
		out->item = yp_scheme_find(key1, key0, conf->scheme);
		if (out->item == NULL) {
			return KNOT_YP_EINVAL_ITEM;
		}
	}

	uint8_t k[CONF_MAX_KEY_LEN];
	namedb_val_t key = { k, CONF_MIN_KEY_LEN };
	namedb_val_t val;

	// Set key0 code.
	int ret = conf_db_code(conf, txn, CONF_CODE_KEY0_ROOT, key0, true,
	                       &k[KEY0_POS]);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Set key1 code.
	if (key1 != NULL) {
		ret = conf_db_code(conf, txn, k[KEY0_POS], key1, true,
		                   &k[KEY1_POS]);
		if (ret != KNOT_EOK) {
			return ret;
		}
	// Set key1 id code.
	} else if (id != NULL && id_len > 0) {
		k[KEY1_POS] = CONF_CODE_KEY1_ID;
	// At least key1 or id must be non-zero.
	} else {
		return KNOT_EINVAL;
	}

	// Fill the item id.
	if (id != NULL && id_len > 0) {
		if (id_len > YP_MAX_ID_LEN) {
			return KNOT_EINVAL;
		}
		memcpy(k + CONF_MIN_KEY_LEN, id, id_len);
		key.len += id_len;
	}

	// Read the data.
	ret = conf->api->find(txn, &key, &val, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Set the output.
	if (out != NULL) {
		out->blob = val.data;
		out->blob_len = val.len;
		out->data = NULL;
		out->len = 0;
	}

	return KNOT_EOK;
}

void conf_db_val(
	conf_val_t *val)
{
	assert(val != NULL);
	assert(val->code == KNOT_EOK || val->code == KNOT_EOF);

	if (val->item->flags & YP_FMULTI) {
		// Check if already called.
		if (val->data != NULL) {
			return;
		}

		assert(val->blob != NULL);
		uint16_t len;
		memcpy(&len, val->blob, sizeof(uint16_t));
		val->len = le16toh(len);
		val->data = val->blob + sizeof(uint16_t);
		val->code = KNOT_EOK;
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

void conf_db_val_next(
	conf_val_t *val)
{
	assert(val != NULL);
	assert(val->code == KNOT_EOK);
	assert(val->item->flags & YP_FMULTI);

	// Check for the 'zero' call.
	if (val->data == NULL) {
		conf_db_val(val);
		return;
	}

	if (val->data + val->len < val->blob + val->blob_len) {
		val->data += val->len;
		uint16_t len;
		memcpy(&len, val->data, sizeof(uint16_t));
		val->len = le16toh(len);
		val->data += sizeof(uint16_t);
		val->code = KNOT_EOK;
	} else {
		val->data = NULL;
		val->len = 0;
		val->code = KNOT_EOF;
	}
}

int conf_db_iter_begin(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0,
	conf_iter_t *iter)
{
	if (conf == NULL || txn == NULL || key0 == NULL || iter == NULL) {
		return KNOT_EINVAL;
	}

	// Look-up group id item in the scheme.
	const yp_item_t *grp = yp_scheme_find(key0, NULL, conf->scheme);
	if (grp == NULL) {
		return KNOT_YP_EINVAL_ITEM;
	}
	assert(grp->type == YP_TGRP);
	iter->item = grp->var.g.id;

	// Get key0 code.
	int ret = conf_db_code(conf, txn, CONF_CODE_KEY0_ROOT, key0, true,
	                       &iter->key0_code);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Prepare key prefix.
	uint8_t k[2] = { iter->key0_code, CONF_CODE_KEY1_ID };
	namedb_val_t key = { k, sizeof(k) };

	// Get the data.
	iter->iter = conf->api->iter_begin(txn, NAMEDB_NOOP);
	iter->iter = conf->api->iter_seek(iter->iter, &key, NAMEDB_GEQ);

	return KNOT_EOK;
}

int conf_db_iter_next(
	conf_t *conf,
	conf_iter_t *iter)
{
	if (conf == NULL || iter == NULL) {
		return KNOT_EINVAL;
	}

	if (iter->iter == NULL) {
		return KNOT_EOK;
	}

	// Move to the next key-value.
	iter->iter = conf->api->iter_next(iter->iter);
	if (iter->iter == NULL) {
		return KNOT_EOF;
	}

	// Get new key.
	namedb_val_t key;
	int ret = conf->api->iter_key(iter->iter, &key);
	if (ret != KNOT_EOK) {
		conf->api->iter_finish(iter->iter);
		return ret;
	}
	uint8_t *key_data = (uint8_t *)key.data;

	// Check for key overflow.
	if (key_data[KEY0_POS] != iter->key0_code ||
	    key_data[KEY1_POS] != CONF_CODE_KEY1_ID) {
		conf->api->iter_finish(iter->iter);
		iter->iter = NULL;
		return KNOT_EOF;
	}

	return KNOT_EOK;
}

void conf_db_iter_finish(
	conf_t *conf,
	conf_iter_t *iter)
{
	if (conf == NULL || iter == NULL) {
		return;
	}

	conf->api->iter_finish(iter->iter);
}

int conf_db_iter_id(
	conf_t *conf,
	conf_iter_t *iter,
	uint8_t **data,
	size_t *data_len)
{
	if (conf == NULL || iter == NULL || data == NULL || data_len == NULL) {
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

int conf_db_raw_dump(
	conf_t *conf,
	const char *file_name)
{
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	FILE *fp = stdout;
	if (file_name != NULL) {
		fp = fopen(file_name, "w");
		if (fp == NULL) {
			return KNOT_ERROR;
		}
	}

	int ret = KNOT_EOK;

	namedb_txn_t txn = conf->read_txn;
	namedb_iter_t *it = conf->api->iter_begin(&txn, NAMEDB_FIRST);
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
		if (k[1] == CONF_CODE_KEY1_ITEMS) {
			fprintf(fp, "[%i][%i]%.*s", k[0], k[1],
			        (int)key.len - 2, k + 2);
			fprintf(fp, ": %u\n", d[0]);
		} else if (k[1] == CONF_CODE_KEY1_ID) {
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
