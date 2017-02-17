/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/dnssec/kasp/kasp_db.h"

#include <stdarg.h> // just for va_free()
#include <pthread.h>
#include <sys/stat.h>

#include "contrib/files.h"
#include "contrib/wire_ctx.h"

struct kasp_db {
	knot_db_t *keys_db;
	knot_db_t *zones_db;
	char *db_path;
	size_t db_mapsize;
	pthread_mutex_t opening_mutex;
};

static const knot_db_api_t *db_api = NULL;

static kasp_db_t *global_kasp_db = NULL;

kasp_db_t **kaspdb()
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

	if (((*db)->keys_db != NULL && (*db)->zones_db == NULL) ||
	    ((*db)->keys_db == NULL && (*db)->zones_db != NULL)) {
		pthread_mutex_unlock(&(*db)->opening_mutex);
		return KNOT_EINVAL;
	}

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

int kasp_db_open(kasp_db_t *db)
{
	if (db == NULL || db->db_path == NULL) {
		return KNOT_EINVAL;
	}

	pthread_mutex_lock(&db->opening_mutex);

	if ((db->keys_db != NULL && db->zones_db == NULL) ||
	    (db->keys_db == NULL && db->zones_db != NULL)) {
		pthread_mutex_unlock(&db->opening_mutex);
		return KNOT_EINVAL;
	}

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
	opts.maxdbs = 2;
	opts.dbname = "keys_db";

	ret = db_api->init(&db->keys_db, NULL, &opts);
	if (ret != KNOT_EOK) {
		pthread_mutex_unlock(&db->opening_mutex);
		return ret;
	}

	opts.dbname = "zones_db";
	opts.flags.db |= KNOT_DB_LMDB_DUPSORT;

	ret = db_api->init(&db->zones_db, NULL, &opts);
	if (ret != KNOT_EOK) {
		db_api->deinit(db->keys_db);
		db->keys_db = NULL;
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
		db_api->deinit((*db)->zones_db);
		(*db)->zones_db = (*db)->keys_db = NULL;
		pthread_mutex_unlock(&(*db)->opening_mutex);
		free((*db)->db_path);
		pthread_mutex_destroy(&(*db)->opening_mutex);
		free(*db);
		*db = NULL;
	}
}

static knot_db_val_t dname2val(const knot_dname_t *dname)
{
	knot_db_val_t res = { .data = knot_dname_copy(dname, NULL) };
	res.len = (res.data == NULL ? 0 : strlen(res.data) + 1);
	return res;
}

static knot_db_val_t dname2val_meta(const knot_dname_t *dname, const char *meta)
{
	assert(dname);
	assert(meta);
	size_t alloc_size = knot_dname_size(dname) + strlen(meta) + 1;
	knot_db_val_t res = { .data = calloc(1, alloc_size), .len = 0 } ;
	if (res.data != NULL) {
		memcpy(res.data, dname, knot_dname_size(dname));
		strcpy(res.data + strlen(res.data) + 1, meta);
		res.len = alloc_size;
	}
	return res;
}

static knot_db_val_t keyid2val(const char *key_id)
{
	knot_db_val_t res = { .len = strlen(key_id) + 1, .data = (void *)key_id };
	return res;
}

static char *val2keyid(const knot_db_val_t *val)
{
	if (strlen(val->data) + 1 != val->len) {
		return NULL;
	}
	char *res = malloc(val->len);
	if (res != NULL) {
		memcpy(res, val->data, val->len);
	}
	return res;
}

static bool val_eq(const knot_db_val_t *a, const knot_db_val_t *b)
{
	if (a->len != b->len || a->len == 0) {
		return (a->len == b->len);
	}
	return (memcmp(a->data, b->data, a->len) == 0);
}

static int serialize_key_params(const key_params_t *params, knot_db_val_t *key, knot_db_val_t *val)
{
	*key = keyid2val(params->id);
	val->len = sizeof(uint16_t) + 2 * sizeof(uint8_t) + 6 * sizeof(uint64_t) +
	            params->public_key.size;
	val->data = malloc(val->len);
	if (val->data == NULL) {
		return KNOT_ENOMEM;
	}
	wire_ctx_t wire = wire_ctx_init(val->data, val->len);

	wire_ctx_write_u64(&wire, params->public_key.size);
	wire_ctx_write_u16(&wire, params->keytag);
	wire_ctx_write_u8(&wire, params->algorithm);
	wire_ctx_write_u8(&wire, (uint8_t)(params->is_ksk ? 0x01 : 0x00));
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.created);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.publish);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.active);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.retire);
	wire_ctx_write_u64(&wire, (uint64_t)params->timing.remove);
	wire_ctx_write(&wire, params->public_key.data, params->public_key.size);

	if (wire.error != KNOT_EOK) {
		free(val->data);
		val->data = NULL;
		val->len = 0;
		return KNOT_ERROR;
	}
	return KNOT_EOK;
}

static int deserialize_key_params(key_params_t *params, const knot_db_val_t *key, const knot_db_val_t *val)
{
	if (params == NULL || key == NULL || val == NULL || key->data == NULL || val->data == NULL ||
	    val->len < sizeof(uint64_t)) {
		return KNOT_EINVAL;
	}

	wire_ctx_t wire = wire_ctx_init(val->data, val->len);
	params->public_key.size = wire_ctx_read_u64(&wire);
	params->keytag = wire_ctx_read_u16(&wire);
	params->algorithm = wire_ctx_read_u8(&wire);
	params->is_ksk = (wire_ctx_read_u8(&wire) != (uint8_t)0x00);
	params->timing.created = (time_t)wire_ctx_read_u64(&wire);
	params->timing.publish = (time_t)wire_ctx_read_u64(&wire);
	params->timing.active = (time_t)wire_ctx_read_u64(&wire);
	params->timing.retire = (time_t)wire_ctx_read_u64(&wire);
	params->timing.remove = (time_t)wire_ctx_read_u64(&wire);
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
	params->id = val2keyid(key);
	if (params->id == NULL) {
		wire.error = KNOT_EMALF;
	}

	if (wire.error != KNOT_EOK || wire_ctx_available(&wire) != 0) {
		free(params->id);
		free(params->public_key.data);
		params->id = NULL;
		params->public_key.data = NULL;
		params->public_key.size = 0;
		return KNOT_EMALF;
	}
	return KNOT_EOK;
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
	ret = db_api->txn_begin((what & 0x2) ? db->zones_db : db->keys_db, txn, (what & 0x1) ? 0 : KNOT_DB_RDONLY); \
	txn_check(__VA_ARGS__); \

#define with_txn_end(...) \
	txn_check(__VA_ARGS__); \
	ret = db_api->txn_commit(txn); \
	if (ret != KNOT_EOK) { \
		db_api->txn_abort(txn); \
	} \

#define KEYS_RO 0x0
#define KEYS_RW 0x1
#define ZONES_RO 0x2
#define ZONES_RW 0x3

// TODO move elsewhere
static void ptrlist_deep_free(list_t *l)
{
	ptrnode_t *n;
	WALK_LIST(n, *l) {
		free(n->d);
	}
	ptrlist_free(l, NULL);
}

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
	if (db == NULL || db->keys_db == NULL || db->zones_db == NULL || zone_name == NULL || dst == NULL) {
		return KNOT_ENOENT;
	}

	with_txn(ZONES_RO, NULL);
	knot_db_val_t key = dname2val(zone_name), val = { 0 };
	knot_db_iter_t *iter = db_api->iter_begin(txn, KNOT_DB_NOOP);
	if (iter != NULL) {
		iter = db_api->iter_seek(iter, &key, 0);
	}

	init_list(dst);
	while (iter != NULL && ret == KNOT_EOK) {
		ret = db_api->iter_key(iter, &val);
		if (ret != KNOT_EOK || !val_eq(&key, &val)) {
			break;
		}
		ret = db_api->iter_val(iter, &val);
		if (ret == KNOT_EOK) {
			ptrlist_add(dst, strdup(val.data), NULL);
			iter = db_api->iter_next(iter);
		}
	}
	db_api->iter_finish(iter);
	db_api->txn_abort(txn);
	free(key.data);

	if (ret != KNOT_EOK) {
		ptrlist_deep_free(dst);
		return ret;
	}
	return (EMPTY_LIST(*dst) ? KNOT_ENOENT : KNOT_EOK);
}

int kasp_db_key_params(kasp_db_t *db, const char *key_id, key_params_t *params)
{
	if (db == NULL || db->keys_db == NULL || db->zones_db == NULL || key_id == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	with_txn(KEYS_RO, NULL);

	knot_db_val_t key = keyid2val(key_id), val = { 0 };
	ret = db_api->find(txn, &key, &val, 0);
	txn_check(NULL);
	ret = deserialize_key_params(params, &key, &val);
	with_txn_end(NULL);
	return ret;
}


// slow: walks through WHOLE database
static int list_zones(kasp_db_t *db, const char *key_id, list_t *zone_list, knot_db_txn_t *req_txn)
{
	if (db == NULL || db->keys_db == NULL || db->zones_db == NULL || key_id == NULL || zone_list == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	knot_db_iter_t *iter = db_api->iter_begin(req_txn, KNOT_DB_FIRST);
	knot_db_val_t key = { 0 }, val = keyid2val(key_id);
	init_list(zone_list);
	while (iter != NULL && ret == KNOT_EOK) {
		ret = db_api->iter_val(iter, &key);
		if (ret != KNOT_EOK) {
			break;
		}
		if (!val_eq(&key, &val)) {
			iter = db_api->iter_next(iter);
			continue;
		}
		ret = db_api->iter_key(iter, &key);
		if (ret == KNOT_EOK) {
			ptrlist_add(zone_list, knot_dname_from_str_alloc(key.data), NULL);
			iter = db_api->iter_next(iter);
		}
	}
	db_api->iter_finish(iter);

	if (ret != KNOT_EOK) {
		ptrlist_deep_free(zone_list);
		return ret;
	}
	return (EMPTY_LIST(*zone_list) ? KNOT_ENOENT : KNOT_EOK);
}

int kasp_db_delete_key(kasp_db_t *db, const knot_dname_t *zone_name, const char *key_id, bool *still_used)
{
	if (db == NULL || db->keys_db == NULL || db->zones_db == NULL || zone_name == NULL || key_id == NULL) {
		return KNOT_EINVAL;
	}

	knot_db_val_t key = dname2val(zone_name), val = keyid2val(key_id);
	list_t lz;
	int lzret;

	{
		with_txn(ZONES_RW, key.data, NULL);
		ret = knot_db_lmdb_del_exact(txn, &key, &val);
		txn_check(key.data, NULL);
		lzret = list_zones(db, key_id, &lz, txn);
		with_txn_end(key.data, NULL);
	}

	with_txn(KEYS_RW, key.data, NULL);
	switch (lzret) {
	case KNOT_ENOENT: // if none of zones uses the key, delete it
		ret = db_api->del(txn, &val);
		*still_used = false;
		break;
	case KNOT_EOK: // other zones still using the key, just free lz
		ptrlist_deep_free(&lz);
		*still_used = true;
		break;
	default: // error occured
		ret = lzret;
	}
	free(key.data);
	with_txn_end(NULL, NULL);
	return ret;
}

int kasp_db_add_key(kasp_db_t *db, const knot_dname_t *zone_name, const key_params_t *params)
{
	if (db == NULL || db->keys_db == NULL || db->zones_db == NULL || zone_name == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	knot_db_val_t key = dname2val(zone_name), keykey = { 0 }, val = { 0 }/*, unused = { 0 }*/;

	{
		with_txn(KEYS_RW, key.data, NULL);
		ret = serialize_key_params(params, &keykey, &val);
		txn_check(key.data, NULL);
		//ret = db_api->find(txn, &keykey, &unused, 0);
		//if (ret != KNOT_ENOENT) {
		//	// TODO handle better
		//	free(keykey.data);
		//	db_api->txn_abort(txn);
		//	return KNOT_EEXIST;
		//} // no check, insert duplicate no problem
		ret = db_api->insert(txn, &keykey, &val, 0);
		with_txn_end(key.data, val.data, NULL);
	}

	with_txn(ZONES_RW, key.data, val.data, NULL);
	ret = db_api->insert(txn, &key, &keykey, 0);
	free(key.data);
	free(val.data);
	with_txn_end(NULL, NULL);
	return ret;
}

int kasp_db_share_key(kasp_db_t *db, const knot_dname_t *zone_name, const char *key_id)
{
	if (db == NULL || db->keys_db == NULL || db->zones_db == NULL || zone_name == NULL || key_id == NULL) {
		return KNOT_EINVAL;
	}

	knot_db_val_t key = dname2val(zone_name), val = keyid2val(key_id), unused = { 0 };

	{
		with_txn(KEYS_RO, key.data, NULL);
		ret = db_api->find(txn, &val, &unused, 0); // check if key exists at all
		with_txn_end(key.data, NULL);
	}


	with_txn(ZONES_RW, key.data, NULL);
	ret = db_api->insert(txn, &key, &val, 0);
	free(key.data);
	with_txn_end(NULL);
	return ret;
}

int kasp_db_store_nsec3salt(kasp_db_t *db, const knot_dname_t *zone_name,
			    const dnssec_binary_t *nsec3salt, time_t salt_created)
{
	if (db == NULL || db->keys_db == NULL || db->zones_db == NULL ||
	    zone_name == NULL || nsec3salt == NULL) {
		return KNOT_EINVAL;
	}

	with_txn(KEYS_RW, NULL);
	knot_db_val_t key = dname2val_meta(zone_name, "nsec3salt");
	knot_db_val_t val = { .len = nsec3salt->size, .data = nsec3salt->data };
	ret = db_api->insert(txn, &key, &val, 0);
	free(key.data);
	txn_check(NULL);
	key = dname2val_meta(zone_name, "nsec3salt_created");
	uint64_t tmp = htobe64(salt_created);
	val.len = sizeof(tmp);
	val.data = &tmp;
	ret = db_api->insert(txn, &key, &val, 0);
	free(key.data);
	with_txn_end(NULL);
	return ret;
}

int kasp_db_load_nsec3salt(kasp_db_t *db, const knot_dname_t *zone_name,
			   dnssec_binary_t *nsec3salt, time_t *salt_created)
{
	if (db == NULL || db->keys_db == NULL || db->zones_db == NULL ||
	    zone_name == NULL || nsec3salt == NULL || salt_created == NULL) {
		return KNOT_EINVAL;
	}

	with_txn(KEYS_RO, NULL);
	knot_db_val_t key = dname2val_meta(zone_name, "nsec3salt_created"), val = { 0 };
	ret = db_api->find(txn, &key, &val, 0);
	free(key.data);
	if (ret == KNOT_EOK) {
		if (val.len == sizeof(uint64_t)) {
			*salt_created = be64toh(*(uint64_t *)val.data);
		}
		else {
			ret = KNOT_EMALF;
		}
	}
	txn_check(NULL);
	key = dname2val_meta(zone_name, "nsec3salt");
	ret = db_api->find(txn, &key, &val, 0);
	free(key.data);
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
