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

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <urcu.h>

#include "contrib/files.h"
#include "knot/catalog/catalog_db.h"
#include "knot/common/log.h"

static const MDB_val catalog_iter_prefix = { 1, "" };

size_t catalog_dname_append(knot_dname_storage_t storage, const knot_dname_t *name)
{
	size_t old_len = knot_dname_size(storage);
	size_t name_len = knot_dname_size(name);
	size_t new_len = old_len - 1 + name_len;
	if (old_len == 0 || name_len == 0 || new_len > KNOT_DNAME_MAXLEN) {
		return 0;
	}
	memcpy(storage + old_len - 1, name, name_len);
	return new_len;
}

int catalog_bailiwick_shift(const knot_dname_t *subname, const knot_dname_t *name)
{
	const knot_dname_t *res = subname;
	while (!knot_dname_is_equal(res, name)) {
		if (*res == '\0') {
			return -1;
		}
		res = knot_wire_next_label(res, NULL);
	}
	return res - subname;
}

void catalog_init(catalog_t *cat, const char *path, size_t mapsize)
{
	knot_lmdb_init(&cat->db, path, mapsize, MDB_NOTLS, NULL);
}

static void ensure_cat_version(knot_lmdb_txn_t *ro_txn, knot_lmdb_txn_t *rw_txn)
{
	MDB_val key = { 8, "\x01version" };
	if (knot_lmdb_find(ro_txn, &key, KNOT_LMDB_EXACT)) {
		if (strncmp(CATALOG_VERSION, ro_txn->cur_val.mv_data,
		            ro_txn->cur_val.mv_size) != 0) {
			log_warning("catalog version mismatch");
		}
	} else if (rw_txn != NULL) {
		MDB_val val = { strlen(CATALOG_VERSION), CATALOG_VERSION };
		knot_lmdb_insert(rw_txn, &key, &val);
	}
}

// does NOT check for catalog zone version by RFC, this is Knot-specific in the cat LMDB !
static void check_cat_version(catalog_t *cat)
{
	if (cat->ro_txn->ret == KNOT_EOK) {
		ensure_cat_version(cat->ro_txn, cat->rw_txn);
	}
}

int catalog_open(catalog_t *cat)
{
	if (!knot_lmdb_is_open(&cat->db)) {
		int ret = knot_lmdb_open(&cat->db);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}
	if (cat->ro_txn == NULL) {
		knot_lmdb_txn_t *ro_txn = calloc(1, sizeof(*ro_txn));
		if (ro_txn == NULL) {
			return KNOT_ENOMEM;
		}
		knot_lmdb_begin(&cat->db, ro_txn, false);
		cat->ro_txn = ro_txn;
	}
	check_cat_version(cat);
	return cat->ro_txn->ret;
}

int catalog_begin(catalog_t *cat)
{
	int ret = catalog_open(cat);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_lmdb_txn_t *rw_txn = calloc(1, sizeof(*rw_txn));
	if (rw_txn == NULL) {
		return KNOT_ENOMEM;
	}
	knot_lmdb_begin(&cat->db, rw_txn, true);
	if (rw_txn->ret != KNOT_EOK) {
		ret = rw_txn->ret;
		free(rw_txn);
		return ret;
	}
	assert(cat->rw_txn == NULL); // LMDB prevents two existing RW txns at a time
	cat->rw_txn = rw_txn;
	check_cat_version(cat);
	return cat->rw_txn->ret;
}

int catalog_commit(catalog_t *cat)
{
	knot_lmdb_txn_t *rw_txn = rcu_xchg_pointer(&cat->rw_txn, NULL);
	knot_lmdb_commit(rw_txn);
	int ret = rw_txn->ret;
	free(rw_txn);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// now refresh RO txn
	knot_lmdb_txn_t *ro_txn = calloc(1, sizeof(*ro_txn));
	if (ro_txn == NULL) {
		return KNOT_ENOMEM;
	}
	knot_lmdb_begin(&cat->db, ro_txn, false);
	cat->old_ro_txn = rcu_xchg_pointer(&cat->ro_txn, ro_txn);

	return KNOT_EOK;
}

void catalog_abort(catalog_t *cat)
{
	knot_lmdb_txn_t *rw_txn = rcu_xchg_pointer(&cat->rw_txn, NULL);
	if (rw_txn != NULL) {
		knot_lmdb_abort(rw_txn);
		free(rw_txn);
	}
}

void catalog_commit_cleanup(catalog_t *cat)
{
	knot_lmdb_txn_t *old_ro_txn = rcu_xchg_pointer(&cat->old_ro_txn, NULL);
	if (old_ro_txn != NULL) {
		knot_lmdb_abort(old_ro_txn);
		free(old_ro_txn);
	}
}

void catalog_deinit(catalog_t *cat)
{
	assert(cat->rw_txn == NULL);
	if (cat->ro_txn != NULL) {
		knot_lmdb_abort(cat->ro_txn);
		free(cat->ro_txn);
	}
	if (cat->old_ro_txn != NULL) {
		knot_lmdb_abort(cat->old_ro_txn);
		free(cat->old_ro_txn);
	}
	knot_lmdb_deinit(&cat->db);
}

int catalog_add(catalog_t *cat, const knot_dname_t *member,
                const knot_dname_t *owner, const knot_dname_t *catzone,
                const char *group)
{
	if (cat->rw_txn == NULL) {
		return KNOT_EINVAL;
	}
	int bail = catalog_bailiwick_shift(owner, catzone);
	if (bail < 0) {
		return KNOT_EOUTOFZONE;
	}
	assert(bail >= 0 && bail < 256);
	MDB_val key = knot_lmdb_make_key("BN", 0, member); // 0 for future purposes
	MDB_val val = knot_lmdb_make_key("BBNS", 0, bail, owner, group);

	knot_lmdb_insert(cat->rw_txn, &key, &val);
	free(key.mv_data);
	free(val.mv_data);
	return cat->rw_txn->ret;
}

int catalog_del(catalog_t *cat, const knot_dname_t *member)
{
	if (cat->rw_txn == NULL) {
		return KNOT_EINVAL;
	}
	MDB_val key = knot_lmdb_make_key("BN", 0, member);
	knot_lmdb_del_prefix(cat->rw_txn, &key); // deletes one record
	free(key.mv_data);
	return cat->rw_txn->ret;
}

static void unmake_val(MDB_val *val, const knot_dname_t **owner,
                       const knot_dname_t **catz, const char **group)
{
	uint8_t zero, shift;
	*group = ""; // backward compatibility with Knot 3.0
	knot_lmdb_unmake_key(val->mv_data, val->mv_size, "BBNS", &zero, &shift,
	                     owner, group);
	*catz = *owner + shift;
}

static int find_threadsafe(catalog_t *cat, const knot_dname_t *member,
                           const knot_dname_t **owner, const knot_dname_t **catz,
                           const char **group, void **tofree)
{
	*tofree = NULL;
	if (cat->ro_txn == NULL) {
		return KNOT_ENOENT;
	}

	MDB_val key = knot_lmdb_make_key("BN", 0, member), val = { 0 };

	int ret = knot_lmdb_find_threadsafe(cat->ro_txn, &key, &val, KNOT_LMDB_EXACT);
	if (ret == KNOT_EOK) {
		unmake_val(&val, owner, catz, group);
		*tofree = val.mv_data;
	}
	free(key.mv_data);
	return ret;
}

int catalog_get_catz(catalog_t *cat, const knot_dname_t *member,
                     const knot_dname_t **catz, const char **group, void **tofree)
{
	const knot_dname_t *unused;
	return find_threadsafe(cat, member, &unused, catz, group, tofree);
}

bool catalog_has_member(catalog_t *cat, const knot_dname_t *member)
{
	const knot_dname_t *catz;
	const char *group;
	void *tofree = NULL;
	int ret = catalog_get_catz(cat, member, &catz, &group, &tofree);
	free(tofree);
	return (ret == KNOT_EOK);
}

bool catalog_contains_exact(catalog_t *cat, const knot_dname_t *member,
                            const knot_dname_t *owner, const knot_dname_t *catz)
{
	const knot_dname_t *found_owner, *found_catz;
	const char *found_group;
	void *tofree = NULL;
	int ret = find_threadsafe(cat, member, &found_owner, &found_catz, &found_group, &tofree);
	if (ret == KNOT_EOK && (!knot_dname_is_equal(owner, found_owner) ||
	    !knot_dname_is_equal(catz, found_catz))) {
		ret = KNOT_ENOENT;
	}
	free(tofree);
	return (ret == KNOT_EOK);
}

typedef struct {
	catalog_apply_cb_t cb;
	void *ctx;
} catalog_apply_ctx_t;

static int catalog_apply_cb(MDB_val *key, MDB_val *val, void *ctx)
{
	catalog_apply_ctx_t *iter_ctx = ctx;
	uint8_t zero;
	const knot_dname_t *mem = NULL, *ow = NULL, *cz = NULL;
	const char *gr = NULL;
	knot_lmdb_unmake_key(key->mv_data, key->mv_size, "BN", &zero, &mem);
	unmake_val(val, &ow, &cz, &gr);
	if (mem == NULL || ow == NULL || cz == NULL) {
		return KNOT_EMALF;
	}
	return iter_ctx->cb(mem, ow, cz, gr, iter_ctx->ctx);
}

int catalog_apply(catalog_t *cat, const knot_dname_t *for_member,
                  catalog_apply_cb_t cb, void *ctx, bool rw)
{
	MDB_val prefix = knot_lmdb_make_key(for_member == NULL ? "B" : "BN", 0, for_member);
	catalog_apply_ctx_t iter_ctx = { cb, ctx };
	knot_lmdb_txn_t *use_txn = rw ? cat->rw_txn : cat->ro_txn;
	int ret = knot_lmdb_apply_threadsafe(use_txn, &prefix, true, catalog_apply_cb, &iter_ctx);
	free(prefix.mv_data);
	return ret;
}

static bool same_catalog(knot_lmdb_txn_t *txn, const knot_dname_t *catalog)
{
	if (catalog == NULL) {
		return true;
	}
	const knot_dname_t *txn_cat = NULL, *unused;
	const char *grunused;
	unmake_val(&txn->cur_val, &unused, &txn_cat, &grunused);
	return knot_dname_is_equal(txn_cat, catalog);
}

int catalog_copy(knot_lmdb_db_t *from, knot_lmdb_db_t *to,
                 const knot_dname_t *cat_only, bool read_rw_txn)
{
	if (knot_lmdb_exists(from) == KNOT_ENODB) {
		return KNOT_EOK;
	}
	int ret = knot_lmdb_open(from);
	if (ret == KNOT_EOK) {
		ret = make_path(to->path, S_IRWXU | S_IRWXG);
		if (ret == KNOT_EOK) {
			ret = knot_lmdb_open(to);
		}
	}
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_lmdb_txn_t txn_r = { 0 }, txn_w = { 0 };
	knot_lmdb_begin(from, &txn_r, read_rw_txn); // using RW txn not to conflict with still-open RO txn
	knot_lmdb_begin(to, &txn_w, true);
	knot_lmdb_foreach(&txn_w, (MDB_val *)&catalog_iter_prefix) {
		if (same_catalog(&txn_w, cat_only)) {
			knot_lmdb_del_cur(&txn_w);
		}
	}
	knot_lmdb_foreach(&txn_r, (MDB_val *)&catalog_iter_prefix) {
		if (same_catalog(&txn_r, cat_only)) {
			knot_lmdb_insert(&txn_w, &txn_r.cur_key, &txn_r.cur_val);
		}
	}
	ensure_cat_version(&txn_w, &txn_w);
	if (txn_r.ret != KNOT_EOK) {
		knot_lmdb_abort(&txn_r);
		knot_lmdb_abort(&txn_w);
		return txn_r.ret;
	}
	knot_lmdb_commit(&txn_r);
	knot_lmdb_commit(&txn_w);
	return txn_w.ret;
}
