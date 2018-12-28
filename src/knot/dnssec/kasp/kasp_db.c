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

#include <inttypes.h>
#include <stdarg.h> // just for va_free()
#include <pthread.h>
#include <sys/stat.h>

#include "contrib/files.h"
#include "contrib/strtonum.h"
#include "contrib/wire_ctx.h"
#include "knot/dnssec/key_records.h"
#include "knot/journal/serialization.h"

struct kasp_db {
	knot_db_t *keys_db;
	char *db_path;
	size_t db_mapsize;
	pthread_mutex_t opening_mutex;
};

typedef enum {
	KASPDBKEY_PARAMS = 0x1,
	KASPDBKEY_POLICYLAST = 0x2,
	KASPDBKEY_NSEC3SALT = 0x3,
	KASPDBKEY_NSEC3TIME = 0x4,
	KASPDBKEY_MASTERSERIAL = 0x5,
	KASPDBKEY_LASTSIGNEDSERIAL = 0x6,
	KASPDBKEY_OFFLINE_RECORDS = 0x7,
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

static MDB_val make_key_str(keyclass_t kclass, const knot_dname_t *dname, const char *str)
{
	switch (kclass) {
	case KASPDBKEY_POLICYLAST:
		assert(dname == NULL && str != NULL);
		return knot_lmdb_make_key("BS", (int)kclass, str);
	case KASPDBKEY_NSEC3SALT:
	case KASPDBKEY_NSEC3TIME:
	case KASPDBKEY_LASTSIGNEDSERIAL:
	case KASPDBKEY_MASTERSERIAL:
		assert(dname != NULL && str == NULL);
		return knot_lmdb_make_key("BN", (int)kclass, dname);
	case KASPDBKEY_PARAMS:
	case KASPDBKEY_OFFLINE_RECORDS:
		assert(dname != NULL);
		if (str == NULL) {
			return knot_lmdb_make_key("BN", (int)kclass, dname);
		} else {
			return knot_lmdb_make_key("BNS", (int)kclass, dname, str);
		}
	}
}

static MDB_val make_key_time(keyclass_t kclass, const knot_dname_t *dname, knot_time_t time)
{
	char tmp[21];
	snprintf(str, sizeof(tmp), "%0*"PRIu64, sizeof(tmp) - 1, time);
	return make_key_str(kclass, dname, tmp);
}

static bool unmake_key_str(const MDB_val *keyv, char **str)
{
	uint8_t kclass;
	const knot_dname_t *dname;
	const char *s;
	return (knot_lmdb_unmake_key(keyv->mv_data, keyv->mv_size, "BNS", &kclass, &dname, &s) &&
		((*str = strdup(s)) != NULL);
}

static bool unmake_key_time(const MDB_val *keyv, knot_time_t *time)
{
	uint8_t kclass;
	const knot_dname_t *dname;
	const char *s;
	return (knot_lmdb_unmake_key(keyv->mv_data, keyv->mv_size, "BNS", &kclass, &dname, &s) &&
		str_to_u64(s, time) == KNOT_EOK);
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

// returns zero time (= infinity) if failure!
static knot_time_t key_time(const knot_db_val_t *key)
{
	uint64_t r = 0;
	(void)str_to_u64(key_str(key), &r);
	return r;
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

static MDB_val params_serialize(const key_params_t *params)
{
	uint8_t flags = 0x02;
	flags |= (params->is_ksk ? 0x01 : 0);
	flags |= (params->is_pub_only ? 0x04 : 0);
	flags |= (params->is_csk ? 0x08 : 0);

	return knot_lmdb_make_key("LLHBBLLLLLLLLLD", (uint64_t)params->public_key.size,
		(uint64_t)0, params->keytag, params->algorithm, flags,
		params->timing.created, params->timing.pre_active, params->timing.publish,
		params->timing.ready, params->timing.active, params->timing.retire_active,
		params->timing.retire, params->timing.post_active, params->timing.remove,
		params->public_key.data, params->public_key.size);
}

// this is no longer compatible with keys created by Knot 2.5.x (and unmodified since)
static bool params_deserialize(const MDB_val *val, key_params_t *params)
{
	if (val->mv_size < 2 * sizeof(uint64_t)) {
		return false;
	}
	uint64_t *_lengths = (uint64_t *)val->mv_data, keylen = _lengths[0], future = _lengths[1];
	uint8_t flags;

	if ((params->public_key.data = malloc(keylen)) == NULL) {
		return false;
	}

	if (knot_lmdb_unmake_key(val->mv_data, val->mv_size = future, "LLHBBLLLLLLLLLD",
		&params->public_key.size, &future, &params->keytag, &params->algorithm, &flags,
		&params->timing.created, &params->timing.pre_active, &params->timing.publish,
		&params->timing.ready, &params->timing.active, &params->timing.retire_active,
		&params->timing.retire, &params->timing.post_active, &params->timing.remove,
		params->public_key.data, keylen)) {

		assert(keylen == params->public_key.size);
		params->is_ksk = ((flags & 0x01) ? true : false);
		params->is_pub_only = ((flags & 0x04) ? true : false);
		params->is_csk = ((flags & 0x08) ? true : false);

		if ((flags & 0x02) && (params->is_ksk || !params->is_csk)) {
			return true;
		}
	}
	free(params->public_key.data);
	return false;
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


static key_params_t *txn2params(knot_lmdb_txn_t *txn)
{
	key_params_t *p = calloc(1, sizeof(*p));
	if (p == NULL) {
		txn->ret = KNOT_ENOMEM;
	} else {
		if (!params_deserialize(&txn.cur_val, p) ||
		    !unmake_key_str(&txn.cur_key, &p->id)) {
			txn->ret = KNOT_EMALF;
			free(p);
			p = NULL;
		}
	}
	return p;
}

int kasp_db_list_keys(knot_lmdb_db_t *db, const knot_dname_t *zone_name, list_t *dst)
{
	init_list(dst);
	knot_lmdb_txn_t txn = { 0 };
	MDB_val prefix = make_key_str(KASPDBKEY_PARAMS, zone_name, NULL);
	knot_lmdb_begin(db, &txn, false);
	knot_lmdb_foreach(&txn, &prefix) {
		key_params_t *p = txn2params(&txn);
		if (p != NULL) {
			ptrlist_add(dst, p, NULL);
		}
	}
	knot_lmdb_abort(&txn);
	free(prefix.mv_data);
	if (txn.ret != KNOT_EOK) {
		ptrlist_deep_free(dst, NULL);
		return txn.ret;
	}
	return (EMPTY_LIST(*dst) ? KNOT_ENOENT : KNOT_EOK);
}

static bool keyid_inuse(knot_lmdb_txn_t *txn, const char *key_id, key_params_t **params)
{
	uint8_t pf = KASPDBKEY_PARAMS;
	MDB_val prefix = { sizeof(pf), &pf };
	knot_lmdb_foreach(txn, &prefix) {
		char *found_id = NULL;
		if (unmake_key_str(&txn->cur_key, &found_id) &&
		    strcmp(found_id, key_id) == 0) {
			if (params != NULL) {
				*params = txn2params(&txn);
			}
			free(found_id);
			return true;
		}
		free(found_id);
	}
	return false;
}


int kasp_db_delete_key(knot_lmdb_db_t *db, const knot_dname_t *zone_name, const char *key_id, bool *still_used)
{
	MDB_val search = make_key_str(KASPDBKEY_PARAMS, zone_name, key_id);
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	knot_lmdb_del_prefix(&txn, &search);
	if (still_used != NULL) {
		*still_used = keyid_inuse(&txn, key_id, NULL);
	}
	knot_lmdb_commit(&txn);
	free(search.mv_data);
	return txn.ret;
}

int kasp_db_add_key(knot_lmdb_db_t *db, const knot_dname_t *zone_name, const key_params_t *params)
{
	MDB_val v = params_serialize(params);
	MDB_val k = make_key_str(KASPDBKEY_PARAMS, zone_name, params->id);
	return knot_lmdb_quick_insert(db, &k, &v);
}

int kasp_db_share_key(knot_lmdb_db_t *db, const knot_dname_t *zone_from,
                      const knot_dname_t *zone_to, const char *key_id)
{
	MDB_val from = make_key_str(KASPDBKEY_PARAMS, zone_from, key_id);
	MDB_val to =   make_key_str(KASPDBKEY_PARAMS, zone_to,   key_id);
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	if (!knot_lmdb_find(&txn, &from, KNOT_LMDB_EXACT)) {
		txn.ret = KNOT_ENOENT;
	} else {
		knot_lmdb_insert(&txn, &to, &txn.cur_val);
	}
	knot_lmdb_commit(&txn);
	free(from.mv_data);
	free(to.mv_data);
	return txn.ret;
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

#define TIME_STRLEN 20
static void for_time2string(char str[TIME_STRLEN + 1], knot_time_t t)
{
	(void)snprintf(str, TIME_STRLEN + 1, "%0*"PRIu64, TIME_STRLEN, t);
}

int kasp_db_store_offline_records(kasp_db_t *db, knot_time_t for_time, const key_records_t *r)
{
	if (db == NULL || r == NULL) {
		return KNOT_EINVAL;
	}

	char for_time_str[TIME_STRLEN + 1];
	for_time2string(for_time_str, for_time);
	knot_db_val_t key = make_key(KASPDBKEY_OFFLINE_RECORDS, r->rrsig.owner, for_time_str), val;
	val.len = key_records_serialized_size(r);
	val.data = malloc(val.len);
	if (val.data == NULL) {
		free_key(&key);
		return KNOT_ENOMEM;
	}
	with_txn(KEYS_RW, key.data, val.data, NULL);
	wire_ctx_t wire = wire_ctx_init(val.data, val.len);
	ret = key_records_serialize(&wire, r);
	if (ret == KNOT_EOK) {
		ret = db_api->insert(txn, &key, &val, 0);
	}
	free_key(&key);
	free_key(&val);
	with_txn_end(NULL);
	return ret;
}

int kasp_db_load_offline_records(kasp_db_t *db, const knot_dname_t *for_dname,
                                 knot_time_t for_time, knot_time_t *next_time,
                                 key_records_t *r)
{
	if (db == NULL || r == NULL) {
		return KNOT_EINVAL;
	}

	char for_time_str[TIME_STRLEN + 1];
	for_time2string(for_time_str, for_time);
	with_txn(KEYS_RO, NULL);
	knot_db_val_t search = make_key(KASPDBKEY_OFFLINE_RECORDS, for_dname, for_time_str), key, val;
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
	if (key_class(&key) != KASPDBKEY_OFFLINE_RECORDS ||
	    knot_dname_cmp((const knot_dname_t *)key.data + 1, for_dname) != 0) {
		ret = KNOT_ENOENT;
		goto cleanup;
	}
	wire_ctx_t wire = wire_ctx_init(val.data, val.len);
	ret = key_records_deserialize(&wire, r);
	if (ret != KNOT_EOK) {
		goto cleanup;
	}
	*next_time = 0;
	if ((it = db_api->iter_next(it)) != NULL && db_api->iter_key(it, &key) == KNOT_EOK) {
		if (key_class(&key) == KASPDBKEY_OFFLINE_RECORDS &&
		    knot_dname_cmp(key_dname(&key), r->rrsig.owner) == 0) {
			*next_time = key_time(&key);
		}
	}
cleanup:
	db_api->iter_finish(it);
	free_key(&search);
	with_txn_end(NULL);
	return ret;
}

int kasp_db_delete_offline_records(kasp_db_t *db, const knot_dname_t *zone,
                                   knot_time_t from_time, knot_time_t to_time)
{
	if (db == NULL) {
		return KNOT_EINVAL;
	}

	with_txn(KEYS_RW, NULL);
	knot_db_iter_t *iter = db_api->iter_begin(txn, KNOT_DB_NOOP);

	char for_time_str[TIME_STRLEN + 1];
	for_time2string(for_time_str, from_time);
	knot_db_val_t key = make_key(KASPDBKEY_OFFLINE_RECORDS, zone, for_time_str);
	iter = db_api->iter_seek(iter, &key, KNOT_DB_GEQ);
	free_key(&key);

	while (ret == KNOT_EOK && iter != NULL && (ret = db_api->iter_key(iter, &key)) == KNOT_EOK &&
	       key.len > TIME_STRLEN && key_class(&key) == KASPDBKEY_OFFLINE_RECORDS &&
	       knot_time_cmp(key_time(&key), to_time) <= 0 &&
	       knot_dname_cmp(key_dname(&key), zone) == 0) {
		ret = knot_db_lmdb_iter_del(iter);
		iter = db_api->iter_next(iter);
	}
	db_api->iter_finish(iter);
	with_txn_end(NULL);
	return ret;
}
