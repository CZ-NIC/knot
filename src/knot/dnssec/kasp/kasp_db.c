/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
	KASPDBKEY_SAVED_TTLS = 0x8,
} keyclass_t;

static const keyclass_t zone_related_classes[] = {
	KASPDBKEY_PARAMS,
	KASPDBKEY_NSEC3SALT,
	KASPDBKEY_NSEC3TIME,
	KASPDBKEY_MASTERSERIAL,
	KASPDBKEY_LASTSIGNEDSERIAL,
	KASPDBKEY_OFFLINE_RECORDS,
	KASPDBKEY_SAVED_TTLS,
};
static const size_t zone_related_classes_size = sizeof(zone_related_classes) / sizeof(*zone_related_classes);

static const keyclass_t key_related_classes[] = {
	KASPDBKEY_PARAMS,
};
static const size_t key_related_classes_size = sizeof(key_related_classes) / sizeof(*key_related_classes);

static bool is_zone_related_class(uint8_t class)
{
	for (size_t i = 0; i < zone_related_classes_size; i++) {
		if (zone_related_classes[i] == class) {
			return true;
		}
	}
	return false;
}

static bool is_zone_related(const MDB_val *key)
{
	return is_zone_related_class(*(uint8_t *)key->mv_data);
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
	case KASPDBKEY_SAVED_TTLS:
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
	default:
		assert(0);
		MDB_val empty = { 0 };
		return empty;
	}
}

static MDB_val make_key_time(keyclass_t kclass, const knot_dname_t *dname, knot_time_t time)
{
	char tmp[21];
	(void)snprintf(tmp, sizeof(tmp), "%0*"PRIu64, (int)(sizeof(tmp) - 1), time);
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
	flags |= (params->is_for_later ? 0x10 : 0);

	return knot_lmdb_make_key("LLHBBLLLLLLLLLDL", (uint64_t)params->public_key.size,
		(uint64_t)sizeof(params->timing.revoke), params->keytag, params->algorithm, flags,
		params->timing.created, params->timing.pre_active, params->timing.publish,
		params->timing.ready, params->timing.active, params->timing.retire_active,
		params->timing.retire, params->timing.post_active, params->timing.remove,
		params->public_key.data, params->public_key.size, params->timing.revoke);
}

// this is no longer compatible with keys created by Knot 2.5.x (and unmodified since)
static bool params_deserialize(const MDB_val *val, key_params_t *params)
{
	if (val->mv_size < 2 * sizeof(uint64_t)) {
		return false;
	}
	uint64_t keylen = knot_wire_read_u64(val->mv_data);
	uint64_t future = knot_wire_read_u64(val->mv_data + sizeof(keylen));
	uint8_t flags;

	if ((params->public_key.data = malloc(keylen)) == NULL) {
		return false;
	}

	if (knot_lmdb_unmake_key(val->mv_data, val->mv_size - future, "LLHBBLLLLLLLLLD",
		&keylen, &future, &params->keytag, &params->algorithm, &flags,
		&params->timing.created, &params->timing.pre_active, &params->timing.publish,
		&params->timing.ready, &params->timing.active, &params->timing.retire_active,
		&params->timing.retire, &params->timing.post_active, &params->timing.remove,
		params->public_key.data, (size_t)keylen)) {

		params->public_key.size = keylen;
		params->is_ksk = ((flags & 0x01) ? true : false);
		params->is_pub_only = ((flags & 0x04) ? true : false);
		params->is_csk = ((flags & 0x08) ? true : false);
		params->is_for_later = ((flags & 0x10) ? true : false);

		if (future > 0) {
			if (future < sizeof(params->timing.revoke)) {
				free(params->public_key.data);
				params->public_key.data = NULL;
				return false;
			}
			// 'revoked' timer is part of 'future' section since it was added later
			params->timing.revoke = knot_wire_read_u64(val->mv_data + val->mv_size - future);
		}

		if ((flags & 0x02) && (params->is_ksk || !params->is_csk)) {
			return true;
		}
	}
	free(params->public_key.data);
	params->public_key.data = NULL;
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

int kasp_db_get_key_algorithm(knot_lmdb_db_t *db, const knot_dname_t *zone_name,
                              const char *key_id)
{
	knot_lmdb_txn_t txn = { 0 };
	MDB_val search = make_key_str(KASPDBKEY_PARAMS, zone_name, key_id);
	knot_lmdb_begin(db, &txn, false);
	int ret = txn.ret == KNOT_EOK ? KNOT_ENOENT : txn.ret;
	if (knot_lmdb_find(&txn, &search, KNOT_LMDB_EXACT)) {
		key_params_t p = { 0 };
		ret = params_deserialize(&txn.cur_val, &p) ? p.algorithm : KNOT_EMALF;
		free(p.public_key.data);
	}
	knot_lmdb_abort(&txn);
	free(search.mv_data);
	return ret;
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
	MDB_val prefix = make_key_str(KASPDBKEY_PARAMS, zone, NULL);
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	for (size_t i = 0; i < zone_related_classes_size && prefix.mv_data != NULL; i++) {
		*(uint8_t *)prefix.mv_data = zone_related_classes[i];
		knot_lmdb_del_prefix(&txn, &prefix);
	}
	knot_lmdb_commit(&txn);
	free(prefix.mv_data);
	return txn.ret;
}

int kasp_db_sweep(knot_lmdb_db_t *db, sweep_cb keep_zone, void *cb_data)
{
	if (knot_lmdb_exists(db) == KNOT_ENODB) {
		return KNOT_EOK;
	}
	int ret = knot_lmdb_open(db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	knot_lmdb_forwhole(&txn) {
		if (is_zone_related(&txn.cur_key) &&
		    !keep_zone((const knot_dname_t *)txn.cur_key.mv_data + 1, cb_data)) {
			knot_lmdb_del_cur(&txn);
		}
	}
	knot_lmdb_commit(&txn);
	return txn.ret;
}

int kasp_db_list_zones(knot_lmdb_db_t *db, list_t *zones)
{
	if (knot_lmdb_exists(db) == KNOT_ENODB) {
		return KNOT_EOK;
	}
	int ret = knot_lmdb_open(db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, false);

	uint8_t prefix_data = KASPDBKEY_PARAMS;
	MDB_val prefix = { sizeof(prefix_data), &prefix_data };
	knot_lmdb_foreach(&txn, &prefix) {
		const knot_dname_t *found = txn.cur_key.mv_data + sizeof(prefix_data);
		if (!knot_dname_is_equal(found, ((ptrnode_t *)TAIL(*zones))->d)) {
			knot_dname_t *copy = knot_dname_copy(found, NULL);
			if (copy == NULL || ptrlist_add(zones, copy, NULL) == NULL) {
				free(copy);
				ptrlist_deep_free(zones, NULL);
				return KNOT_ENOMEM;
			}
		}
	}
	knot_lmdb_abort(&txn);
	if (txn.ret != KNOT_EOK) {
		ptrlist_deep_free(zones, NULL);
	}
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
	knot_lmdb_begin(db, &txn, false);
	if (nsec3salt != NULL) {
		memset(nsec3salt, 0, sizeof(*nsec3salt));
		if (knot_lmdb_find(&txn, &key, KNOT_LMDB_EXACT | KNOT_LMDB_FORCE)) {
			nsec3salt->size = txn.cur_val.mv_size;
			nsec3salt->data = malloc(txn.cur_val.mv_size + 1); // +1 because it can be zero
			if (nsec3salt->data == NULL) {
				txn.ret = KNOT_ENOMEM;
			} else {
				memcpy(nsec3salt->data, txn.cur_val.mv_data, txn.cur_val.mv_size);
			}
		}
	}
	*(uint8_t *)key.mv_data = KASPDBKEY_NSEC3TIME;
	if (knot_lmdb_find(&txn, &key, KNOT_LMDB_EXACT | KNOT_LMDB_FORCE)) {
		knot_lmdb_unmake_curval(&txn, "L", salt_created);
	}
	knot_lmdb_abort(&txn);
	free(key.mv_data);
	if (txn.ret != KNOT_EOK && nsec3salt != NULL) {
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
	if (knot_lmdb_exists(db) == KNOT_ENODB) {
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
		assert(*lp_zone != NULL && *lp_keyid != NULL);
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
		    (last_lp_keyid == NULL || strcmp(last_lp_keyid, real_last_keyid) != 0)) {
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
                                 knot_time_t *for_time, knot_time_t *next_time,
                                 key_records_t *r)
{
	MDB_val prefix = make_key_str(KASPDBKEY_OFFLINE_RECORDS, for_dname, NULL);
	if (prefix.mv_data == NULL) {
		return KNOT_ENOMEM;
	}
	unsigned operator = KNOT_LMDB_GEQ;
	MDB_val search = prefix;
	bool zero_for_time = (*for_time == 0);
	if (!zero_for_time) {
		operator = KNOT_LMDB_LEQ;
		search = make_key_time(KASPDBKEY_OFFLINE_RECORDS, for_dname, *for_time);
	}
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, false);
	if (knot_lmdb_find(&txn, &search, operator) &&
	    knot_lmdb_is_prefix_of(&prefix, &txn.cur_key)) {
		wire_ctx_t wire = wire_ctx_init(txn.cur_val.mv_data, txn.cur_val.mv_size);
		txn.ret = key_records_deserialize(&wire, r);
		if (zero_for_time) {
			unmake_key_time(&txn.cur_key, for_time);
		}
		if (!knot_lmdb_next(&txn) || !knot_lmdb_is_prefix_of(&prefix, &txn.cur_key) ||
		    !unmake_key_time(&txn.cur_key, next_time)) {
			*next_time = 0;
		}
	} else if (txn.ret == KNOT_EOK) {
		txn.ret = KNOT_ENOENT;
	}
	knot_lmdb_abort(&txn);
	if (!zero_for_time) {
		free(search.mv_data);
	}
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

int kasp_db_get_saved_ttls(knot_lmdb_db_t *db, const knot_dname_t *zone,
                           uint32_t *max_ttl, uint32_t *key_ttl)
{
	MDB_val key = make_key_str(KASPDBKEY_SAVED_TTLS, zone, NULL);
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, false);
	if (knot_lmdb_find(&txn, &key, KNOT_LMDB_EXACT | KNOT_LMDB_FORCE)) {
		knot_lmdb_unmake_curval(&txn, "II", max_ttl, key_ttl);
	}
	knot_lmdb_abort(&txn);
	free(key.mv_data);
	return txn.ret;
}

int kasp_db_set_saved_ttls(knot_lmdb_db_t *db, const knot_dname_t *zone,
                           uint32_t max_ttl, uint32_t key_ttl)
{
	MDB_val key = make_key_str(KASPDBKEY_SAVED_TTLS, zone, NULL);
	MDB_val val = knot_lmdb_make_key("II", max_ttl, key_ttl);
	return knot_lmdb_quick_insert(db, key, val);
}

void kasp_db_ensure_init(knot_lmdb_db_t *db, conf_t *conf)
{
	if (db->path == NULL) {
		char *kasp_dir = conf_db(conf, C_KASP_DB);
		conf_val_t kasp_size = conf_db_param(conf, C_KASP_DB_MAX_SIZE);
		knot_lmdb_init(db, kasp_dir, conf_int(&kasp_size), 0, "keys_db");
		free(kasp_dir);
		assert(db->path != NULL);
	}
}

static int kasp_db_backup_generic(const knot_dname_t *zone, knot_lmdb_db_t *db, knot_lmdb_db_t *backup_db,
                                  const keyclass_t *classes, const size_t classes_size)
{
	size_t n_prefs = classes_size;

	// NOTE: for full KASP db backup, this must match number of record types
	MDB_val prefixes[n_prefs + 1]; // last one reserved for KASPDBKEY_POLICYLAST

	for (size_t i = 0; i < n_prefs; i++) {
		prefixes[i] = make_key_str(classes[i], zone, NULL);
	}

	if (classes == zone_related_classes) {
		// we copy all policy-last records, that doesn't harm
		prefixes[n_prefs++] = knot_lmdb_make_key("B", KASPDBKEY_POLICYLAST);
	}

	int ret = knot_lmdb_copy_prefixes(db, backup_db, prefixes, n_prefs);

	for (int i = 0; i < n_prefs; i++) {
		free(prefixes[i].mv_data);
	}
	return ret;
}

int kasp_db_backup(const knot_dname_t *zone, knot_lmdb_db_t *db, knot_lmdb_db_t *backup_db)
{
	return kasp_db_backup_generic(zone, db, backup_db,
	                              zone_related_classes, zone_related_classes_size);
}

int kasp_db_backup_keys(const knot_dname_t *zone, knot_lmdb_db_t *db, knot_lmdb_db_t *backup_db)
{
	return kasp_db_backup_generic(zone, db, backup_db,
	                              key_related_classes, key_related_classes_size);
}
