/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdio.h>

#include "contrib/strtonum.h"
#include "contrib/wire_ctx.h"
#include "knot/dnssec/key_records.h"

typedef enum {
	KASPDBKEY_PARAMS = 0x1,
	KASPDBKEY_POLICYLAST = 0x2,
	KASPDBKEY_NSEC3SALT = 0x3,
	KASPDBKEY_NSEC3TIME = 0x4,
	KASPDBKEY_MASTERSERIAL = 0x5,
	KASPDBKEY_LASTSIGNEDSERIAL = 0x6,
	KASPDBKEY_OFFLINE_RECORDS = 0x7,
} keyclass_t;

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
	snprintf(tmp, sizeof(tmp), "%0*"PRIu64, (int)(sizeof(tmp) - 1), time);
	return make_key_str(kclass, dname, tmp);
}

static bool unmake_key_str(const MDB_val *keyv, char **str)
{
	uint8_t kclass;
	const knot_dname_t *dname;
	const char *s;
	return (knot_lmdb_unmake_key(keyv->mv_data, keyv->mv_size, "BNS", &kclass, &dname, &s) &&
		((*str = strdup(s)) != NULL));
}

static bool unmake_key_time(const MDB_val *keyv, knot_time_t *time)
{
	uint8_t kclass;
	const knot_dname_t *dname;
	const char *s;
	return (knot_lmdb_unmake_key(keyv->mv_data, keyv->mv_size, "BNS", &kclass, &dname, &s) &&
		str_to_u64(s, time) == KNOT_EOK);
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
	uint64_t *_lengths = (uint64_t *)val->mv_data;
	uint64_t keylen = be64toh(_lengths[0]), future = be64toh(_lengths[1]);
	uint8_t flags;

	if ((params->public_key.data = malloc(keylen)) == NULL) {
		return false;
	}

	if (knot_lmdb_unmake_key(val->mv_data, val->mv_size - future, "LLHBBLLLLLLLLLD",
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

static key_params_t *txn2params(knot_lmdb_txn_t *txn)
{
	key_params_t *p = calloc(1, sizeof(*p));
	if (p == NULL) {
		txn->ret = KNOT_ENOMEM;
	} else {
		if (!params_deserialize(&txn->cur_val, p) ||
		    !unmake_key_str(&txn->cur_key, &p->id)) {
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
				*params = txn2params(txn);
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


int kasp_db_delete_all(knot_lmdb_db_t *db, const knot_dname_t *zone)
{
	keyclass_t del_classes[] = { KASPDBKEY_NSEC3SALT, KASPDBKEY_NSEC3TIME,
		KASPDBKEY_LASTSIGNEDSERIAL, KASPDBKEY_MASTERSERIAL,
		KASPDBKEY_PARAMS, KASPDBKEY_OFFLINE_RECORDS, };
	MDB_val prefix = make_key_str(KASPDBKEY_PARAMS, zone, NULL);
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	for (int i = 0; i < sizeof(del_classes) / sizeof(*del_classes) && prefix.mv_data != NULL; i++) {
		*(uint8_t *)prefix.mv_data = del_classes[i];
		knot_lmdb_del_prefix(&txn, &prefix);
	}
	knot_lmdb_commit(&txn);
	free(prefix.mv_data);
	return txn.ret;
}

int kasp_db_add_key(knot_lmdb_db_t *db, const knot_dname_t *zone_name, const key_params_t *params)
{
	MDB_val v = params_serialize(params);
	MDB_val k = make_key_str(KASPDBKEY_PARAMS, zone_name, params->id);
	return knot_lmdb_quick_insert(db, k, v);
}

int kasp_db_share_key(knot_lmdb_db_t *db, const knot_dname_t *zone_from,
                      const knot_dname_t *zone_to, const char *key_id)
{
	MDB_val from = make_key_str(KASPDBKEY_PARAMS, zone_from, key_id);
	MDB_val to =   make_key_str(KASPDBKEY_PARAMS, zone_to,   key_id);
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	if (knot_lmdb_find(&txn, &from, KNOT_LMDB_EXACT | KNOT_LMDB_FORCE)) {
		knot_lmdb_insert(&txn, &to, &txn.cur_val);
	}
	knot_lmdb_commit(&txn);
	free(from.mv_data);
	free(to.mv_data);
	return txn.ret;
}

int kasp_db_store_nsec3salt(knot_lmdb_db_t *db, const knot_dname_t *zone_name,
			    const dnssec_binary_t *nsec3salt, knot_time_t salt_created)
{
	MDB_val key = make_key_str(KASPDBKEY_NSEC3SALT, zone_name, NULL);
	MDB_val val1 = { nsec3salt->size, nsec3salt->data };
	uint64_t tmp = htobe64(salt_created);
	MDB_val val2 = { sizeof(tmp), &tmp };
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	knot_lmdb_insert(&txn, &key, &val1);
	if (key.mv_data != NULL) {
		*(uint8_t *)key.mv_data = KASPDBKEY_NSEC3TIME;
	}
	knot_lmdb_insert(&txn, &key, &val2);
	knot_lmdb_commit(&txn);
	free(key.mv_data);
	return txn.ret;
}

int kasp_db_load_nsec3salt(knot_lmdb_db_t *db, const knot_dname_t *zone_name,
			   dnssec_binary_t *nsec3salt, knot_time_t *salt_created)
{
	MDB_val key = make_key_str(KASPDBKEY_NSEC3SALT, zone_name, NULL);
	knot_lmdb_txn_t txn = { 0 };
	memset(nsec3salt, 0, sizeof(*nsec3salt));
	knot_lmdb_begin(db, &txn, false);
	if (knot_lmdb_find(&txn, &key, KNOT_LMDB_EXACT | KNOT_LMDB_FORCE)) {
		nsec3salt->size = txn.cur_val.mv_size;
		nsec3salt->data = malloc(txn.cur_val.mv_size);
		if (nsec3salt->data == NULL) {
			txn.ret = KNOT_ENOMEM;
		} else {
			memcpy(nsec3salt->data, txn.cur_val.mv_data, txn.cur_val.mv_size);
		}
		*(uint8_t *)key.mv_data = KASPDBKEY_NSEC3TIME;
	}
	if (knot_lmdb_find(&txn, &key, KNOT_LMDB_EXACT | KNOT_LMDB_FORCE)) {
		knot_lmdb_unmake_curval(&txn, "L", salt_created);
	}
	knot_lmdb_abort(&txn);
	free(key.mv_data);
	if (txn.ret != KNOT_EOK) {
		free(nsec3salt->data);
	}
	return txn.ret;
}

int kasp_db_store_serial(knot_lmdb_db_t *db, const knot_dname_t *zone_name,
			 kaspdb_serial_t serial_type, uint32_t serial)
{
	int ret = knot_lmdb_open(db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	MDB_val k = make_key_str((keyclass_t)serial_type, zone_name, NULL);
	MDB_val v = knot_lmdb_make_key("I", serial);
	return knot_lmdb_quick_insert(db, k, v);
}

int kasp_db_load_serial(knot_lmdb_db_t *db, const knot_dname_t *zone_name,
			kaspdb_serial_t serial_type, uint32_t *serial)
{
	if (!knot_lmdb_exists(db)) {
		return KNOT_ENOENT;
	}
	int ret = knot_lmdb_open(db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	MDB_val k = make_key_str((keyclass_t)serial_type, zone_name, NULL);
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, false);
	if (knot_lmdb_find(&txn, &k, KNOT_LMDB_EXACT | KNOT_LMDB_FORCE)) {
		knot_lmdb_unmake_curval(&txn, "I", serial);
	}
	knot_lmdb_abort(&txn);
	free(k.mv_data);
	return txn.ret;
}

int kasp_db_get_policy_last(knot_lmdb_db_t *db, const char *policy_string,
                            knot_dname_t **lp_zone, char **lp_keyid)
{
	MDB_val k = make_key_str(KASPDBKEY_POLICYLAST, NULL, policy_string);
	uint8_t kclass = 0;
	knot_lmdb_txn_t txn = { 0 };
	*lp_zone = NULL;
	*lp_keyid = NULL;
	knot_lmdb_begin(db, &txn, false);
	if (knot_lmdb_find(&txn, &k, KNOT_LMDB_EXACT | KNOT_LMDB_FORCE) &&
	    knot_lmdb_unmake_curval(&txn, "BNS", &kclass, lp_zone, lp_keyid)) {
		*lp_zone = knot_dname_copy(*lp_zone, NULL);
		*lp_keyid = strdup(*lp_keyid);
		if (kclass != KASPDBKEY_PARAMS) {
			txn.ret = KNOT_EMALF;
		} else if (*lp_keyid == NULL || *lp_zone == NULL) {
			txn.ret = KNOT_ENOMEM;
		} else {
			// check that the referenced key really exists
			knot_lmdb_find(&txn, &txn.cur_val, KNOT_LMDB_EXACT | KNOT_LMDB_FORCE);
		}
	}
	knot_lmdb_abort(&txn);
	free(k.mv_data);
	if (txn.ret != KNOT_EOK) {
		free(*lp_zone);
		free(*lp_keyid);
	}
	return txn.ret;
}

int kasp_db_set_policy_last(knot_lmdb_db_t *db, const char *policy_string, const char *last_lp_keyid,
			    const knot_dname_t *new_lp_zone, const char *new_lp_keyid)
{
	MDB_val k = make_key_str(KASPDBKEY_POLICYLAST, NULL, policy_string);
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	if (knot_lmdb_find(&txn, &k, KNOT_LMDB_EXACT)) {
		// check that the last_lp_keyid matches
		uint8_t unuse1, *unuse2;
		const char *real_last_keyid;
		if (knot_lmdb_unmake_curval(&txn, "BNS", &unuse1, &unuse2, &real_last_keyid) &&
		    strcmp(last_lp_keyid, real_last_keyid) != 0) {
			txn.ret = KNOT_ESEMCHECK;
		}
	}
	MDB_val v = make_key_str(KASPDBKEY_PARAMS, new_lp_zone, new_lp_keyid);
	knot_lmdb_insert(&txn, &k, &v);
	free(k.mv_data);
	free(v.mv_data);
	knot_lmdb_commit(&txn);
	return txn.ret;
}

static void add_dname_to_list(list_t *dst, const knot_dname_t *dname, int *ret)
{
	ptrnode_t *n;
	WALK_LIST(n, *dst) {
		if (knot_dname_is_equal(n->d, dname)) {
			return;
		}
	}
	knot_dname_t *copy = knot_dname_copy(dname, NULL);
	if (copy == NULL) {
		*ret = KNOT_ENOMEM;
	} else {
		ptrlist_add(dst, copy, NULL);
	}
}

int kasp_db_list_zones(knot_lmdb_db_t *db, list_t *dst)
{
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, false);
	init_list(dst);
	bool found = knot_lmdb_first(&txn);
	while (found) {
		const knot_dname_t *zone;
		if (*(uint8_t *)txn.cur_key.mv_data != KASPDBKEY_POLICYLAST &&
		    knot_dname_size((zone = txn.cur_key.mv_data + 1)) < txn.cur_key.mv_size) {
			add_dname_to_list(dst, zone, &txn.ret);
		}
		found = knot_lmdb_next(&txn);
	}
	knot_lmdb_abort(&txn);
	if (txn.ret != KNOT_EOK) {
		ptrlist_deep_free(dst, NULL);
		return txn.ret;
	}
	return (EMPTY_LIST(*dst) ? KNOT_ENOENT : KNOT_EOK);
}

int kasp_db_store_offline_records(knot_lmdb_db_t *db, knot_time_t for_time, const key_records_t *r)
{
	MDB_val k = make_key_time(KASPDBKEY_OFFLINE_RECORDS, r->rrsig.owner, for_time);
	MDB_val v = { key_records_serialized_size(r), NULL };
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	if (knot_lmdb_insert(&txn, &k, &v)) {
		wire_ctx_t wire = wire_ctx_init(v.mv_data, v.mv_size);
		txn.ret = key_records_serialize(&wire, r);
	}
	knot_lmdb_commit(&txn);
	free(k.mv_data);
	return txn.ret;
}

int kasp_db_load_offline_records(knot_lmdb_db_t *db, const knot_dname_t *for_dname,
                                 knot_time_t for_time, knot_time_t *next_time,
                                 key_records_t *r)
{
	MDB_val prefix = make_key_str(KASPDBKEY_OFFLINE_RECORDS, for_dname, NULL);
	if (prefix.mv_data == NULL) {
		return KNOT_ENOMEM;
	}
	MDB_val search = make_key_time(KASPDBKEY_OFFLINE_RECORDS, for_dname, for_time);
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, false);
	if (knot_lmdb_find(&txn, &search, KNOT_LMDB_LEQ) &&
	    knot_lmdb_is_prefix_of(&prefix, &txn.cur_key)) {
		wire_ctx_t wire = wire_ctx_init(txn.cur_val.mv_data, txn.cur_val.mv_size);
		txn.ret = key_records_deserialize(&wire, r);
		if (!knot_lmdb_next(&txn) || !knot_lmdb_is_prefix_of(&prefix, &txn.cur_key) ||
		    !unmake_key_time(&txn.cur_key, next_time)) {
			*next_time = 0;
		}
	} else if (txn.ret == KNOT_EOK) {
		txn.ret = KNOT_ENOENT;
	}
	knot_lmdb_abort(&txn);
	free(search.mv_data);
	free(prefix.mv_data);
	return txn.ret;
}

int kasp_db_delete_offline_records(knot_lmdb_db_t *db, const knot_dname_t *zone,
                                   knot_time_t from_time, knot_time_t to_time)
{
	MDB_val prefix = make_key_str(KASPDBKEY_OFFLINE_RECORDS, zone, NULL);
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	knot_lmdb_foreach(&txn, &prefix) {
		knot_time_t found;
		if (unmake_key_time(&txn.cur_key, &found) &&
		    knot_time_cmp(found, from_time) >= 0 &&
		    knot_time_cmp(found, to_time) <= 0) {
			knot_lmdb_del_cur(&txn);
		}
	}
	knot_lmdb_commit(&txn);
	free(prefix.mv_data);
	return txn.ret;
}
