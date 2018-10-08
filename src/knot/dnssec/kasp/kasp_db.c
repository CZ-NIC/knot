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

#include "knot/dnssec/kasp/kasp_db.h"

#include <stdarg.h> // just for va_free()
#include <pthread.h>
#include <sys/stat.h>

#include "contrib/files.h"
#include "contrib/wire_ctx.h"
#include "knot/journal/serialization.h"

struct kasp_db {
	knot_db_t *keys_db;
	char *db_path;
	size_t db_mapsize;
	pthread_mutex_t opening_mutex;
};

typedef enum {
	KASPDBKEY_OFFLINE_RRSIG = 0x0, // this MUST be always first, because we use LEQ operator
	KASPDBKEY_PARAMS = 0x1,
	KASPDBKEY_POLICYLAST = 0x2,
	KASPDBKEY_NSEC3SALT = 0x3,
	KASPDBKEY_NSEC3TIME = 0x4,
	KASPDBKEY_MASTERSERIAL = 0x5,
	KASPDBKEY_LASTSIGNEDSERIAL = 0x6,
} keyclass_t;

static const knot_db_api_t *db_api = NULL;

static kasp_db_t *global_kasp_db = NULL;

kasp_db_t **kaspdb(void)
{
	return &global_kasp_db;
}

int kasp_db_init(kasp_db_t **db, const char *path, size_t mapsize)
{
	if (db == NULL || path == NULL || *db != NULL) {
		return KNOT_EINVAL;
	}

	db_api = knot_db_lmdb_api();

	*db = calloc(1, sizeof(**db));
	if (*db == NULL) {
		return KNOT_ENOMEM;
	}

	(*db)->db_path = strdup(path);
	if ((*db)->db_path == NULL) {
		free(*db);
		return KNOT_ENOMEM;
	}

	(*db)->db_mapsize = mapsize;

	pthread_mutex_init(&(*db)->opening_mutex, NULL);
	return KNOT_EOK;
}

int kasp_db_reconfigure(kasp_db_t **db, const char *new_path, size_t new_mapsize)
{
	if (db == NULL || new_path == NULL || *db == NULL || (*db)->db_path == NULL) {
		return KNOT_EINVAL;
	}

	pthread_mutex_lock(&(*db)->opening_mutex);

	bool changed_path = (strcmp(new_path, (*db)->db_path) != 0);
	bool changed_mapsize = (new_mapsize != (*db)->db_mapsize);

	if ((*db)->keys_db != NULL) {
		pthread_mutex_unlock(&(*db)->opening_mutex);
		if (changed_path) {
			return KNOT_EBUSY;
		} else if (changed_mapsize) {
			return KNOT_EEXIST;
		} else {
			return KNOT_ENODIFF;
		}
	}

	free((*db)->db_path);
	(*db)->db_path = strdup(new_path);
	if ((*db)->db_path == NULL) {
		pthread_mutex_unlock(&(*db)->opening_mutex);
		return KNOT_ENOMEM;
	}
	(*db)->db_mapsize = new_mapsize;

	pthread_mutex_unlock(&(*db)->opening_mutex);
	return KNOT_EOK;
}

bool kasp_db_exists(kasp_db_t *db)
{
	if (db->keys_db == NULL) {
		struct stat st;
		if (stat(db->db_path, &st) != 0) {
			return false;
		}
	}
	return true;
}

int kasp_db_open(kasp_db_t *db)
{
	if (db == NULL || db->db_path == NULL) {
		return KNOT_EINVAL;
	}

	pthread_mutex_lock(&db->opening_mutex);

	if (db->keys_db != NULL) {
		pthread_mutex_unlock(&db->opening_mutex);
		return KNOT_EOK; // already open
	}

	int ret = make_dir(db->db_path, S_IRWXU | S_IRGRP | S_IXGRP, true);
	if (ret != KNOT_EOK) {
		pthread_mutex_unlock(&db->opening_mutex);
		return ret;
	}

	struct knot_db_lmdb_opts opts = KNOT_DB_LMDB_OPTS_INITIALIZER;
	opts.path = db->db_path;
	opts.mapsize = db->db_mapsize;
	opts.maxdbs = 1;
	opts.dbname = "keys_db";

	ret = db_api->init(&db->keys_db, NULL, &opts);
	if (ret != KNOT_EOK) {
		pthread_mutex_unlock(&db->opening_mutex);
		return ret;
	}

	pthread_mutex_unlock(&db->opening_mutex);

	return ret;
}

void kasp_db_close(kasp_db_t **db)
{
	if (db != NULL && *db != NULL) {
		pthread_mutex_lock(&(*db)->opening_mutex);
		db_api->deinit((*db)->keys_db);
		(*db)->keys_db = NULL;
		pthread_mutex_unlock(&(*db)->opening_mutex);
		free((*db)->db_path);
		pthread_mutex_destroy(&(*db)->opening_mutex);
		free(*db);
		*db = NULL;
	}
}

static knot_db_val_t make_key(keyclass_t kclass, const knot_dname_t *dname, const char *str)
{
	size_t dnlen = knot_dname_size(dname);
	size_t slen = (str == NULL ? 0 : strlen(str) + 1);
	knot_db_val_t res = { .len = 1 + dnlen + slen, .data = malloc(1 + dnlen + slen) };
	if (res.data != NULL) {
		wire_ctx_t wire = wire_ctx_init(res.data, res.len);
		wire_ctx_write_u8(&wire, (uint8_t)kclass);
		wire_ctx_write(&wire, dname, dnlen);
		wire_ctx_write(&wire, str, slen);
	} else {
		res.len = 0;
	}
	return res;
}

static keyclass_t key_class(const knot_db_val_t *key)
{
	return ((uint8_t *)key->data)[0];
}

static const knot_dname_t *key_dname(const knot_db_val_t *key)
{
	return (key->data + 1);
}

static const char *key_str(const knot_db_val_t *key)
{
	return (key->data + 1 + knot_dname_size(key_dname(key)));
}

static void free_key(knot_db_val_t *key)
{
	free(key->data);
	memset(key, 0, sizeof(*key));
}

static char *keyid_fromkey(const knot_db_val_t *key)
{
	if (key->len < 2 || *(uint8_t *)key->data != KASPDBKEY_PARAMS) {
		return NULL;
	}
	size_t skip = knot_dname_size((const uint8_t *)key->data + 1);
	return (key->len < skip + 2 ? NULL : strdup(key->data + skip + 1));
}

static bool check_key_zone(const knot_db_val_t *key, const knot_dname_t *zone_name)
{
	if (key->len < 2 || *(uint8_t *)key->data == KASPDBKEY_POLICYLAST) {
		return false;
	}
	return knot_dname_is_equal(key->data + 1, zone_name);
}

static int serialize_key_params(const key_params_t *params, const knot_dname_t *dname, knot_db_val_t *key, knot_db_val_t *val)
{
	assert(params != NULL);
	assert(dname != NULL);
	assert(key != NULL);
	assert(val != NULL);

	*key = make_key(KASPDBKEY_PARAMS, dname, params->id);
	val->len = sizeof(uint16_t) + 2 * sizeof(uint8_t) + 11 * sizeof(uint64_t) +
	            params->public_key.size;
	val->data = malloc(val->len);
	if (val->data == NULL) {
		free(key->data);
		key->data = NULL;
		key->len = 0;
		return KNOT_ENOMEM;
	}
	wire_ctx_t wire = wire_ctx_init(val->data, val->len);

	wire_ctx_write_u64(&wire, params->public_key.size);
	wire_ctx_write_u64(&wire, 0); // length of Unused-future block at the end
	wire_ctx_write_u16(&wire, params->keytag);
	wire_ctx_write_u8(&wire, params->algorithm);
	uint8_t flags = 0x02;
	flags |= (params->is_ksk ? 0x01 : 0);
	flags |= (params->is_pub_only ? 0x04 : 0);
	flags |= (params->is_csk ? 0x08 : 0);
	wire_ctx_write_u8(&wire, flags);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.created);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.pre_active);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.publish);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.ready);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.active);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.retire_active);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.retire);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.post_active);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.remove);
	wire_ctx_write(&wire, params->public_key.data, params->public_key.size);

	if (wire.error != KNOT_EOK) {
		free(key->data);
		free(val->data);
		key->data = NULL;
		key->len = 0;
		val->data = NULL;
		val->len = 0;
		return KNOT_ERROR;
	}
	return KNOT_EOK;
}

static int deserialize_key_params(key_params_t *params, const knot_db_val_t *key, const knot_db_val_t *val)
{
	assert(params != NULL);
	assert(key != NULL);
	assert(val != NULL);
	assert(key->data != NULL);
	assert(val->data != NULL);
	assert(val->len >= sizeof(uint64_t));

	wire_ctx_t wire = wire_ctx_init_const(val->data, val->len);
	params->public_key.size = wire_ctx_read_u64(&wire);
	uint64_t unused_future_length = wire_ctx_read_u64(&wire);
	params->keytag = wire_ctx_read_u16(&wire);
	params->algorithm = wire_ctx_read_u8(&wire);
	uint8_t isksk_plus_flags = wire_ctx_read_u8(&wire);
	params->is_ksk = ((isksk_plus_flags & (uint8_t)0x01) != (uint8_t)0x00);
	params->is_pub_only = ((isksk_plus_flags & (uint8_t)0x04) != (uint8_t)0x00);
	params->is_csk = ((isksk_plus_flags & (uint8_t)0x08) != (uint8_t)0x00);
	if (params->is_csk && !params->is_ksk) {
		return KNOT_EMALF;
	}
	if ((isksk_plus_flags & (uint8_t)0x02) != (uint8_t)0x00) {
		params->timing.created = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.pre_active = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.publish = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.ready = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.active = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.retire_active = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.retire = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.post_active = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.remove = (knot_time_t)wire_ctx_read_u64(&wire);
	} else {
		// import of old kasp db format missing some timers
		params->timing.created = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.pre_active = 0;
		params->timing.publish = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.ready = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.active = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.retire_active = 0;
		params->timing.retire = (knot_time_t)wire_ctx_read_u64(&wire);
		params->timing.post_active = 0;
		params->timing.remove = (knot_time_t)wire_ctx_read_u64(&wire);
	}
	if (wire.error != KNOT_EOK) {
		return KNOT_ERROR;
	}

	free(params->public_key.data);
	params->public_key.data = malloc(params->public_key.size);
	if (params->public_key.data == NULL) {
		return KNOT_ENOMEM;
	}
	wire_ctx_read(&wire, params->public_key.data, params->public_key.size);

	free(params->id);
	params->id = keyid_fromkey(key);
	if (params->id == NULL) {
		wire.error = KNOT_EMALF;
	}

	if (wire.error != KNOT_EOK || wire_ctx_available(&wire) != unused_future_length) {
		free(params->id);
		free(params->public_key.data);
		params->id = NULL;
		params->public_key.data = NULL;
		params->public_key.size = 0;
		return KNOT_EMALF;
	}
	return KNOT_EOK;
}

static key_params_t *keyval2params(const knot_db_val_t *key, const knot_db_val_t *val)
{
	key_params_t *res = calloc(1, sizeof(*res));
	if (res != NULL) {
		if (deserialize_key_params(res, key, val) != KNOT_EOK) {
			free(res);
			return NULL;
		}
	}
	return res;
}

#define txn_check(...) \
	if (ret != KNOT_EOK) { \
		db_api->txn_abort(txn); \
		va_free(NULL, __VA_ARGS__); \
		return ret; \
	} \

#define with_txn(what, ...) \
	int ret = KNOT_EOK; \
	knot_db_txn_t local_txn, *txn = &local_txn; \
	ret = db_api->txn_begin(db->keys_db, txn, (what & 0x1) ? 0 : KNOT_DB_RDONLY); \
	txn_check(__VA_ARGS__); \

#define with_txn_end(...) \
	txn_check(__VA_ARGS__); \
	ret = db_api->txn_commit(txn); \
	if (ret != KNOT_EOK) { \
		db_api->txn_abort(txn); \
	} \

#define KEYS_RO 0x0
#define KEYS_RW 0x1

// TODO move elsewhere
static void va_free(void *p, ...)
{
	va_list args;
	va_start(args, p);
	for (void *f = p; f != NULL; f = va_arg(args, void *)) {
		free(f);
	}
	va_end(args);
}

int kasp_db_list_keys(kasp_db_t *db, const knot_dname_t *zone_name, list_t *dst)
{
	if (db == NULL || db->keys_db == NULL || zone_name == NULL || dst == NULL) {
		return KNOT_ENOENT;
	}

	knot_db_val_t key = make_key(KASPDBKEY_PARAMS, zone_name, NULL), val = { 0 };

	with_txn(KEYS_RO, NULL);
	knot_db_iter_t *iter = db_api->iter_begin(txn, KNOT_DB_NOOP);
	if (iter != NULL) {
		iter = db_api->iter_seek(iter, &key, KNOT_DB_GEQ);
	}
	free_key(&key);

	init_list(dst);
	while (iter != NULL && ret == KNOT_EOK) {
		ret = db_api->iter_key(iter, &key);
		if (ret != KNOT_EOK || *(uint8_t *)key.data != KASPDBKEY_PARAMS || !check_key_zone(&key, zone_name)) {
			break;
		}
		ret = db_api->iter_val(iter, &val);
		if (ret == KNOT_EOK) {
			key_params_t *parm = keyval2params(&key, &val);
			if (parm != NULL) {
				ptrlist_add(dst, parm, NULL);
			}
			iter = db_api->iter_next(iter);
		}
	}
	db_api->iter_finish(iter);
	db_api->txn_abort(txn);

	if (ret != KNOT_EOK) {
		ptrlist_deep_free(dst, NULL);
		return ret;
	}
	return (EMPTY_LIST(*dst) ? KNOT_ENOENT : KNOT_EOK);
}

static bool keyid_inuse(knot_db_txn_t *txn, const char *key_id, key_params_t **optional)
{
	knot_db_iter_t *iter = db_api->iter_begin(txn, KNOT_DB_FIRST);
	while (iter != NULL) {
		knot_db_val_t key, val;
		if (db_api->iter_key(iter, &key) == KNOT_EOK && *(uint8_t *)key.data == KASPDBKEY_PARAMS) {
			char *keyid = keyid_fromkey(&key);
			if (keyid != NULL && strcmp(keyid, key_id) == 0) {
				if (optional != NULL && db_api->iter_val(iter, &val) == KNOT_EOK) {
					*optional = keyval2params(&key, &val);
				}
				db_api->iter_finish(iter);
				free(keyid);
				return true;
			}
			free(keyid);
		}
		iter = db_api->iter_next(iter);
	}
	db_api->iter_finish(iter);
	return false;
}

int kasp_db_delete_key(kasp_db_t *db, const knot_dname_t *zone_name, const char *key_id, bool *still_used)
{
	if (db == NULL || db->keys_db == NULL || zone_name == NULL || key_id == NULL) {
		return KNOT_EINVAL;
	}

	knot_db_val_t key = make_key(KASPDBKEY_PARAMS, zone_name, key_id);

	with_txn(KEYS_RW, key.data, NULL);
	ret = db_api->del(txn, &key);
	free_key(&key);
	if (still_used != NULL) {
		*still_used = keyid_inuse(txn, key_id, NULL);
	}
	with_txn_end(NULL, NULL);
	return ret;
}

int kasp_db_delete_all(kasp_db_t *db, const knot_dname_t *zone_name)
{
	list_t allkeys;
	init_list(&allkeys);
	int r = kasp_db_list_keys(db, zone_name, &allkeys);
	if (r != KNOT_EOK) {
		return r;
	}

	with_txn(KEYS_RW, NULL);

	ptrnode_t *n;
	WALK_LIST(n, allkeys) {
		key_params_t *parm = n->d;
		knot_db_val_t key = make_key(KASPDBKEY_PARAMS, zone_name, parm->id);
		(void)db_api->del(txn, &key);
		free_key(&key);
		free(parm->id);
		free(parm->public_key.data);
		memset(parm, 0, sizeof(*parm));
	}
	ptrlist_deep_free(&allkeys, NULL);

	for (keyclass_t keyclass = KASPDBKEY_NSEC3SALT; keyclass <= KASPDBKEY_LASTSIGNEDSERIAL; keyclass++) {
		knot_db_val_t key = make_key(keyclass, zone_name, NULL);
		(void)db_api->del(txn, &key);
		free_key(&key);
	}

	with_txn_end(NULL, NULL);
	return ret;
}

int kasp_db_add_key(kasp_db_t *db, const knot_dname_t *zone_name, const key_params_t *params)
{
	if (db == NULL || db->keys_db == NULL || zone_name == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	knot_db_val_t key = { 0 }, val = { 0 };

	with_txn(KEYS_RW, NULL);
	ret = serialize_key_params(params, zone_name, &key, &val);
	txn_check(NULL);
	ret = db_api->insert(txn, &key, &val, 0);
	free_key(&key);
	free_key(&val);
	with_txn_end(NULL, NULL);
	return ret;
}

int kasp_db_share_key(kasp_db_t *db, const knot_dname_t *zone_from, const knot_dname_t *zone_to, const char *key_id)
{
	if (db == NULL || db->keys_db == NULL || zone_from == NULL ||
	    zone_to == NULL || key_id == NULL) {
		return KNOT_EINVAL;
	}

	knot_db_val_t key_from = make_key(KASPDBKEY_PARAMS, zone_from, key_id),
	              key_to = make_key(KASPDBKEY_PARAMS, zone_to, key_id), val = { 0 };

	with_txn(KEYS_RW, NULL);
	ret = db_api->find(txn, &key_from, &val, 0);
	txn_check(txn, key_from.data, key_to.data, NULL);
	ret = db_api->insert(txn, &key_to, &val, 0);
	free_key(&key_from);
	free_key(&key_to);
	with_txn_end(NULL);
	return ret;
}

int kasp_db_store_nsec3salt(kasp_db_t *db, const knot_dname_t *zone_name,
			    const dnssec_binary_t *nsec3salt, knot_time_t salt_created)
{
	if (db == NULL || db->keys_db == NULL ||
	    zone_name == NULL || nsec3salt == NULL || salt_created <= 0) {
		return KNOT_EINVAL;
	}

	with_txn(KEYS_RW, NULL);
	knot_db_val_t key = make_key(KASPDBKEY_NSEC3SALT, zone_name, NULL);
	knot_db_val_t val = { .len = nsec3salt->size, .data = nsec3salt->data };
	ret = db_api->insert(txn, &key, &val, 0);
	free_key(&key);
	txn_check(NULL);
	key = make_key(KASPDBKEY_NSEC3TIME, zone_name, NULL);
	uint64_t tmp = htobe64((uint64_t)salt_created);
	val.len = sizeof(tmp);
	val.data = &tmp;
	ret = db_api->insert(txn, &key, &val, 0);
	free_key(&key);
	with_txn_end(NULL);
	return ret;
}

int kasp_db_load_nsec3salt(kasp_db_t *db, const knot_dname_t *zone_name,
			   dnssec_binary_t *nsec3salt, knot_time_t *salt_created)
{
	if (db == NULL || db->keys_db == NULL ||
	    zone_name == NULL || nsec3salt == NULL || salt_created == NULL) {
		return KNOT_EINVAL;
	}

	with_txn(KEYS_RW, NULL);
	knot_db_val_t key = make_key(KASPDBKEY_NSEC3TIME, zone_name, NULL), val = { 0 };
	ret = db_api->find(txn, &key, &val, 0);
	free_key(&key);
	if (ret == KNOT_EOK) {
		if (val.len == sizeof(uint64_t)) {
			*salt_created = (knot_time_t)be64toh(*(uint64_t *)val.data);
		}
		else {
			ret = KNOT_EMALF;
		}
	}
	txn_check(NULL);
	key = make_key(KASPDBKEY_NSEC3SALT, zone_name, NULL);
	ret = db_api->find(txn, &key, &val, 0);
	free_key(&key);
	if (ret == KNOT_EOK) {
		nsec3salt->data = malloc(val.len);
		if (nsec3salt->data == NULL) {
			ret = KNOT_ENOMEM;
		} else {
			nsec3salt->size = val.len;
			memcpy(nsec3salt->data, val.data, val.len);
		}
	}
	with_txn_end(NULL);
	return ret;
}

int kasp_db_store_serial(kasp_db_t *db, const knot_dname_t *zone_name,
			 kaspdb_serial_t serial_type, uint32_t serial)
{
	if (db == NULL || db->keys_db == NULL || zone_name == NULL) {
		return KNOT_EINVAL;
	}

	uint32_t be = htobe32(serial);
	with_txn(KEYS_RW, NULL);
	knot_db_val_t key = make_key((keyclass_t)serial_type, zone_name, NULL);
	knot_db_val_t val = { .len = sizeof(uint32_t), .data = &be };
	ret = db_api->insert(txn, &key, &val, 0);
	free_key(&key);
	with_txn_end(NULL);
	return ret;
}

int kasp_db_load_serial(kasp_db_t *db, const knot_dname_t *zone_name,
			kaspdb_serial_t serial_type, uint32_t *serial)
{
	if (db == NULL || db->keys_db == NULL || zone_name == NULL || serial == NULL) {
		return KNOT_EINVAL;
	}

	with_txn(KEYS_RO, NULL);
	knot_db_val_t key = make_key((keyclass_t)serial_type, zone_name, NULL), val = { 0 };
	ret = db_api->find(txn, &key, &val, 0);
	free_key(&key);
	if (ret == KNOT_EOK) {
		if (val.len == sizeof(uint32_t)) {
			*serial = be32toh(*(uint32_t *)val.data);
		} else {
			ret = KNOT_EMALF;
		}
	}
	with_txn_end(NULL);
	return ret;
}

int kasp_db_get_policy_last(kasp_db_t *db, const char *policy_string, knot_dname_t **lp_zone,
			    char **lp_keyid)
{
	if (db == NULL || db->keys_db == NULL || policy_string == NULL ||
	    lp_zone == NULL || lp_keyid == NULL) {
		return KNOT_EINVAL;
	}

	with_txn(KEYS_RO, NULL);
	knot_db_val_t key = make_key(KASPDBKEY_POLICYLAST, NULL, policy_string), val = { 0 };
	ret = db_api->find(txn, &key, &val, 0);
	free_key(&key);
	if (ret == KNOT_EOK) {
		if (*(uint8_t *)val.data != KASPDBKEY_PARAMS) {
			ret = KNOT_EMALF;
		} else {
			*lp_zone = knot_dname_copy((knot_dname_t *)(val.data + 1), NULL);
			*lp_keyid = keyid_fromkey(&val);
			if (*lp_zone == NULL || *lp_keyid == NULL) {
				free(*lp_zone);
				free(*lp_keyid);
				ret = KNOT_ENOMEM;
			} else {
				// check that the shared key ID really exists
				key = make_key(KASPDBKEY_PARAMS, *lp_zone, *lp_keyid);
				ret = db_api->find(txn, &key, &val, 0);
				free_key(&key);
				if (ret != KNOT_EOK) {
					free(*lp_zone);
					free(*lp_keyid);
				}
			}
		}
	}
	with_txn_end(NULL);
	return ret;
}

int kasp_db_set_policy_last(kasp_db_t *db, const char *policy_string, const char *last_lp_keyid,
			    const knot_dname_t *new_lp_zone, const char *new_lp_keyid)
{
	if (db == NULL || db->keys_db == NULL ||
	    new_lp_zone == NULL || new_lp_keyid == NULL) {
		return KNOT_EINVAL;
	}
	with_txn(KEYS_RW, NULL);
	knot_db_val_t key = make_key(KASPDBKEY_POLICYLAST, NULL, policy_string), val = { 0 };
	ret = db_api->find(txn, &key, &val, 0);
	switch (ret) {
	case KNOT_EOK:
		if (*(uint8_t *)val.data != KASPDBKEY_PARAMS) {
			ret = KNOT_EMALF;
		} else {
			char *real_last = keyid_fromkey(&val);
			if (real_last == NULL) {
				ret = KNOT_ENOMEM;
			} else {
				if (last_lp_keyid == NULL || strcmp(real_last, last_lp_keyid) != 0) {
					ret = KNOT_ESEMCHECK;
				}
				free(real_last);
			}
		}
		break;
	case KNOT_ENOENT:
		ret = KNOT_EOK;
		break;
	}
	if (ret == KNOT_EOK) {
		val = make_key(KASPDBKEY_PARAMS, new_lp_zone, new_lp_keyid);
		ret = db_api->insert(txn, &key, &val, 0);
		free(val.data);
	}
	free(key.data);
	with_txn_end(NULL);
	return ret;
}

int kasp_db_list_zones(kasp_db_t *db, list_t *dst)
{
	if (db == NULL || db->keys_db == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	with_txn(KEYS_RO, NULL);
	knot_db_iter_t *iter = db_api->iter_begin(txn, KNOT_DB_FIRST);
	while (iter != NULL) {
		knot_db_val_t key;
		if (db_api->iter_key(iter, &key) == KNOT_EOK && key.len > 1 &&
		    *(uint8_t *)key.data != KASPDBKEY_POLICYLAST) {
			// obtain a domain name of a record in KASP db
			knot_dname_t *key_dn = (knot_dname_t *)(key.data + 1);
			// check if not already in dst
			ptrnode_t *n;
			WALK_LIST(n, *dst) {
				knot_dname_t *exist_dn = (knot_dname_t *)n->d;
				if (knot_dname_is_equal(key_dn, exist_dn)) {
					key_dn = NULL;
					break;
				}
			}
			// copy it from txn and add to dst
			if (key_dn != NULL) {
				knot_dname_t *add_dn = knot_dname_copy(key_dn, NULL);
				if (add_dn == NULL) {
					ret = KNOT_ENOMEM;
					break;
				}
				ptrlist_add(dst, add_dn, NULL);
			}
		}
		iter = db_api->iter_next(iter);
	}
	db_api->iter_finish(iter);
	db_api->txn_abort(txn);

	if (ret != KNOT_EOK) {
		ptrlist_deep_free(dst, NULL);
		return ret;
	}
	return (EMPTY_LIST(*dst) ? KNOT_ENOENT : KNOT_EOK);
}

static void for_time2string(char str[21], knot_time_t t)
{
	snprintf(str, 21, "%020lu", t);
}

int kasp_db_store_offline_rrsig(kasp_db_t *db, knot_time_t for_time, const knot_rrset_t *rrsig, const knot_rrset_t *dnskey,
                                const knot_rrset_t *cdnskey, const knot_rrset_t *cds)
{
	if (db == NULL || rrsig == NULL || rrsig->type != KNOT_RRTYPE_RRSIG || dnskey == NULL || dnskey->type != KNOT_RRTYPE_DNSKEY ||
	    cdnskey == NULL || cdnskey->type != KNOT_RRTYPE_CDNSKEY || cds == NULL || cds->type != KNOT_RRTYPE_CDS) {
		return KNOT_EINVAL;
	}

	char for_time_str[21];
	for_time2string(for_time_str, for_time);
	knot_db_val_t key = make_key(KASPDBKEY_OFFLINE_RRSIG, rrsig->owner, for_time_str), val;
	val.len = rrset_serialized_size(rrsig) + rrset_serialized_size(dnskey) +
	          rrset_serialized_size(cdnskey) + rrset_serialized_size(cds);
	val.data = malloc(val.len);
	if (val.data == NULL) {
		free_key(&key);
		return KNOT_ENOMEM;
	}
	with_txn(KEYS_RW, NULL);
	wire_ctx_t wire = wire_ctx_init(val.data, val.len);
	ret = serialize_rrset(&wire, rrsig);
	if (ret == KNOT_EOK) {
		ret = serialize_rrset(&wire, dnskey);
	}
	if (ret == KNOT_EOK) {
		ret = serialize_rrset(&wire, cdnskey);
	}
	if (ret == KNOT_EOK) {
		ret = serialize_rrset(&wire, cds);
	}
	if (ret == KNOT_EOK) {
		ret = db_api->insert(txn, &key, &val, 0);
	}
	free_key(&key);
	with_txn_end(NULL);
	return ret;
}

int kasp_db_load_offline_rrsig(kasp_db_t *db, const knot_dname_t *for_dname, knot_time_t for_time, knot_time_t *next_time,
			       knot_rrset_t *rrsig, knot_rrset_t *dnskey, knot_rrset_t *cdnskey, knot_rrset_t *cds)
{
	if (db == NULL || rrsig == NULL || dnskey == NULL || cdnskey == NULL || cds == NULL) {
		return KNOT_EINVAL;
	}

	char for_time_str[21];
	for_time2string(for_time_str, for_time);
	with_txn(KEYS_RO, NULL);
	knot_db_val_t search = make_key(KASPDBKEY_OFFLINE_RRSIG, for_dname, for_time_str), key, val;
	knot_db_iter_t *it = db_api->iter_begin(txn, KNOT_DB_NOOP);
	if (it == NULL) {
		ret = KNOT_ERROR;
		goto cleanup;
	}
	it = db_api->iter_seek(it, &search, KNOT_DB_LEQ);
	if (it == NULL) {
		ret = KNOT_ENOENT;
		goto cleanup;
	}
	if (db_api->iter_key(it, &key) != KNOT_EOK || db_api->iter_val(it, &val) != KNOT_EOK) {
		ret = KNOT_ERROR;
		goto cleanup;
	}
	if (knot_dname_cmp((const knot_dname_t *)key.data + 1, rrsig->owner) != 0) {
		ret = KNOT_ENOENT;
		goto cleanup;
	}
	wire_ctx_t wire = wire_ctx_init(val.data, val.len);
#define CHK_RET if (ret != KNOT_EOK) goto cleanup;
	ret = deserialize_rrset(&wire, rrsig);
	CHK_RET
	ret = deserialize_rrset(&wire, dnskey);
	CHK_RET
	ret = deserialize_rrset(&wire, cdnskey);
	CHK_RET
	ret = deserialize_rrset(&wire, cds);
	CHK_RET
#undef CHK_RET
	*next_time = 0;
	if ((it = db_api->iter_next(it)) != NULL && db_api->iter_key(it, &key) == KNOT_EOK) {
		if (knot_dname_cmp(key_dname(&key), rrsig->owner) == 0) {
			*next_time = atol(key_str(&key));
		}
	}
cleanup:
	db_api->iter_finish(it);
	free_key(&search);
	with_txn_end(NULL);
	return ret;
}

int kasp_db_delete_offline_rrsig(kasp_db_t *db, const knot_dname_t *zone, knot_time_t from, knot_time_t to)
{
	if (db == NULL) {
		return KNOT_EINVAL;
	}

	with_txn(KEYS_RW, NULL);
	knot_db_iter_t *iter = db_api->iter_begin(txn, KNOT_DB_NOOP);

	char for_time_str[21];
	for_time2string(for_time_str, from);
	knot_db_val_t key = make_key(KASPDBKEY_OFFLINE_RRSIG, zone, for_time_str);
	iter = db_api->iter_seek(iter, &key, KNOT_DB_GEQ);
	free_key(&key);

	while (ret == KNOT_EOK && iter != NULL && (ret = db_api->iter_key(iter, &key)) == KNOT_EOK &&
	       key.len > 20 && key_class(&key) == KASPDBKEY_OFFLINE_RRSIG &&
	       knot_time_cmp(atol(key_str(&key)), to) <= 0 &&
	       knot_dname_cmp(key_dname(&key), zone) == 0) {
		ret = knot_db_lmdb_iter_del(iter);
		iter = db_api->iter_next(iter);
	}
	db_api->iter_finish(iter);
	with_txn_end(NULL);
	return ret;
}
