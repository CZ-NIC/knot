/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/zone/catalog.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "knot/conf/conf.h"
#include "knot/zone/contents.h"

int knot_catalog_init(knot_catalog_t *cat, const char *path, size_t mapsize)
{
	knot_lmdb_init(&cat->db, path, mapsize, 0, NULL);
	int ret = knot_lmdb_open(&cat->db);
	if (ret != KNOT_EOK) {
		knot_lmdb_deinit(&cat->db);
		return ret;
	}
	knot_lmdb_begin(&cat->db, &cat->txn, true);
	if (cat->txn.ret != KNOT_EOK) {
		knot_lmdb_deinit(&cat->db);
	}
	return cat->txn.ret;
}

int knot_catalog_deinit(knot_catalog_t *cat)
{
	knot_lmdb_commit(&cat->txn);
	knot_lmdb_deinit(&cat->db);
	return cat->txn.ret;
}

static int bailiwick_shift(const knot_dname_t *subname, const knot_dname_t *name)
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

int knot_catalog_add(knot_catalog_t *cat, const knot_dname_t *member,
                     const knot_dname_t *owner, const knot_dname_t *catzone)
{
	int bail = bailiwick_shift(owner, catzone);
	if (bail < 0) {
		return KNOT_EOUTOFZONE;
	}
	assert(bail >= 0 && bail < 256);
	MDB_val key = knot_lmdb_make_key("BN", 0, member); // 0 for future purposes
	MDB_val val = knot_lmdb_make_key("BBN", 0, bail, owner);

	knot_lmdb_insert(&cat->txn, &key, &val);
	free(key.mv_data);
	free(val.mv_data);
	return cat->txn.ret;
}

int knot_catalog_del(knot_catalog_t *cat, const knot_dname_t *member)
{
	MDB_val key = knot_lmdb_make_key("BN", 0, member);
	knot_lmdb_del_prefix(&cat->txn, &key); // deletes one record
	free(key.mv_data);
	return cat->txn.ret;
}

void knot_catalog_curval(knot_catalog_t *cat, const knot_dname_t **member,
                         const knot_dname_t **owner, const knot_dname_t **catzone)
{
	uint8_t zero, shift;
	if (member != NULL) {
		knot_lmdb_unmake_key(cat->txn.cur_key.mv_data, cat->txn.cur_key.mv_size, "BN", &zero, member);
	}
	const knot_dname_t *ow;
	knot_lmdb_unmake_curval(&cat->txn, "BBN", &zero, &shift, &ow);
	if (owner != NULL) {
		*owner = ow;
	}
	if (catzone != NULL) {
		*catzone = ow + shift;
	}
}

int knot_catalog_get_catzone(knot_catalog_t *cat, const knot_dname_t *member,
                             const knot_dname_t **catzone)
{
	MDB_val key = knot_lmdb_make_key("BN", 0, member);
	if (knot_lmdb_find(&cat->txn, &key, KNOT_LMDB_EXACT)) {
		knot_catalog_curval(cat, NULL, NULL, catzone);
		free(key.mv_data);
		return KNOT_EOK;
	}
	free(key.mv_data);
	return MIN(cat->txn.ret, KNOT_ENOENT);
}

knot_cat_find_res_t knot_catalog_find(knot_catalog_t *cat, const knot_dname_t *member,
                                      const knot_dname_t *owner, const knot_dname_t *catzone)
{
	MDB_val key = knot_lmdb_make_key("BN", 0, member);
	int ret = MEMBER_NONE;
	if (knot_lmdb_find(&cat->txn, &key, KNOT_LMDB_EXACT)) {
		const knot_dname_t *ow, *cz;
		knot_catalog_curval(cat, NULL, &ow, &cz);
		if (!knot_dname_is_equal(cz, catzone)) {
			ret = MEMBER_ZONE;
		} else if (!knot_dname_is_equal(ow, owner)) {
			ret = MEMBER_OWNER;
		} else {
			ret = MEMBER_EXACT;
		}
	}
	if (cat->txn.ret != KNOT_EOK) {
		ret = MEMBER_ERROR;
	}
	free(key.mv_data);
	return ret;
}

int knot_cat_update_init(knot_cat_update_t *u)
{
	u->add = trie_create(NULL);
	if (u->add == NULL) {
		return KNOT_ENOMEM;
	}
	u->rem = trie_create(NULL);
	if (u->rem == NULL) {
		trie_free(u->add);
		return KNOT_ENOMEM;
	}
	pthread_mutex_init(&u->mutex, 0);
	return KNOT_EOK;
}

static int freecb(trie_val_t *tval, void *unused)
{
	(void)unused;
	free(*(void **)tval);
	return 0;
}

void knot_cat_update_clear(knot_cat_update_t *u)
{
	trie_apply(u->add, freecb, NULL);
	trie_clear(u->add);
	trie_apply(u->rem, freecb, NULL);
	trie_clear(u->rem);
}

void knot_cat_update_deinit(knot_cat_update_t *u)
{
	pthread_mutex_destroy(&u->mutex);
	trie_free(u->add);
	trie_free(u->rem);
}

int knot_cat_update_add(knot_cat_update_t *u, const knot_dname_t *member,
                        const knot_dname_t *owner, const knot_dname_t *catzone,
                        bool remove)
{
	int bail = bailiwick_shift(owner, catzone);
	if (bail < 0) {
		return KNOT_EOUTOFZONE;
	}
	assert(bail >= 0 && bail < 256);

	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(member, lf_storage);

	trie_t *toadd = remove ? u->rem : u->add;
	trie_t *check = remove ? u->add : u->rem;

	bool just_reconf = false;

	trie_val_t *found = trie_get_try(check, lf + 1, lf[0]);
	if (found != NULL) {
		knot_cat_upd_val_t *counter = *found;
		assert(knot_dname_is_equal(counter->member, member));
		if (knot_dname_is_equal(counter->owner, owner)) {
			assert(knot_dname_is_equal(counter->catzone, catzone));
			trie_del(check, lf + 1, lf[0], NULL);
			return KNOT_EOK;
		} else {
			counter->just_reconf = true;
			just_reconf = true;
		}
	}

	size_t member_size = knot_dname_size(member);
	size_t owner_size = knot_dname_size(owner);

	knot_cat_upd_val_t *val = malloc(sizeof(*val) + member_size + owner_size);
	if (val == NULL) {
		return KNOT_ENOMEM;
	}
	trie_val_t *added = trie_get_ins(toadd, lf + 1, lf[0]);
	if (added == NULL) {
		free(val);
		return KNOT_ENOMEM;
	}
	if (*added != NULL) { // rewriting existing val
		free(*added);
	}
	val->member = (knot_dname_t *)(val + 1);
	val->owner = val->member + member_size;
	val->catzone = val->owner + bail;
	memcpy(val->member, member, member_size);
	memcpy(val->owner, owner, owner_size);
	val->just_reconf = just_reconf;
	*added = val;
	return KNOT_EOK;
}

knot_cat_upd_val_t *knot_cat_update_get(knot_cat_update_t *u, const knot_dname_t *member, bool remove)
{
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(member, lf_storage);

	trie_val_t *found = trie_get_try(remove ? u->rem : u->add, lf + 1, lf[0]);
	return found == NULL ? NULL : *(knot_cat_upd_val_t **)found;
}

typedef struct {
	knot_cat_update_t *u;
	const knot_dname_t *apex;
	bool remove;
	knot_catalog_t *check;
} cat_upd_ctx_t;

static int cat_update_add_node(zone_node_t *node, void *data)
{
	cat_upd_ctx_t *ctx = data;
	const knot_rdataset_t *ptr = node_rdataset(node, KNOT_RRTYPE_PTR);
	if (ptr == NULL || ptr->count == 0) {
		return KNOT_EOK;
	}
	knot_rdata_t *rdata = ptr->rdata;
	int ret = KNOT_EOK;
	for (int i = 0; ret == KNOT_EOK && i < ptr->count; i++) {
		const knot_dname_t *member = (const knot_dname_t *)rdata;
		if (ctx->check != NULL && ctx->remove &&
		    knot_catalog_find(ctx->check, member, node->owner, ctx->apex) != MEMBER_EXACT) {
			rdata = knot_rdataset_next(rdata);
			continue;
		}
		ret = knot_cat_update_add(ctx->u, member, node->owner, ctx->apex, ctx->remove);
		rdata = knot_rdataset_next(rdata);
	}
	return ret;
}

int knot_cat_update_from_zone(knot_cat_update_t *u, struct zone_contents *zone,
                              bool remove, knot_catalog_t *check)
{
	cat_upd_ctx_t ctx = { u, zone->apex->owner, remove, check };
	pthread_mutex_lock(&u->mutex);
	int ret = zone_contents_apply(zone, cat_update_add_node, &ctx);
	pthread_mutex_unlock(&u->mutex);
	return ret;
}

int knot_cat_update_del_all(knot_cat_update_t *u, knot_catalog_t *cat, const knot_dname_t *zone)
{
	pthread_mutex_lock(&u->mutex);
	knot_lmdb_forwhole(&cat->txn) { // TODO possible speedup by indexing which member zones belong to a catalog zone
		const knot_dname_t *mem, *ow, *cz;
		knot_catalog_curval(cat, &mem, &ow, &cz);
		if (knot_dname_is_equal(cz, zone)) {
			int ret = knot_cat_update_add(u, mem, ow, cz, true);
			if (ret != KNOT_EOK) {
				pthread_mutex_unlock(&u->mutex);
				return ret;
			}
		}
	}
	pthread_mutex_unlock(&u->mutex);
	return cat->txn.ret;
}

// TODO remove
int knot_cat_update_check(knot_cat_update_t *u, knot_catalog_t *against, const knot_dname_t *zone_only)
{
	pthread_mutex_lock(&u->mutex);
	list_t todel;
	init_list(&todel);
	knot_cat_it_t *it = knot_cat_it_begin(u, true);
	while (!knot_cat_it_finised(it)) {
		knot_cat_upd_val_t *val = knot_cat_it_val(it);
		if (zone_only == NULL || knot_dname_is_equal(zone_only, val->catzone)) {
			if (knot_catalog_find(against, val->member, val->owner, val->catzone) != MEMBER_EXACT) {
				ptrlist_add(&todel, val->member, NULL);
			}
		}
		knot_cat_it_next(it);
	}
	knot_cat_it_free(it);

	ptrnode_t *n;
	WALK_LIST(n, todel) {
		// TODO
	}
	ptrlist_free(&todel, NULL);
	pthread_mutex_unlock(&u->mutex);
	return KNOT_EOK;
}

