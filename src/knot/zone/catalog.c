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

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/zone/contents.h"

#define CATALOG_VERSION "1.0"

const MDB_val knot_catalog_iter_prefix = { 1, "" };

void knot_catalog_init(knot_catalog_t *cat, const char *path, size_t mapsize)
{
	knot_lmdb_init(&cat->db, path, mapsize, 0, NULL);
}

int knot_catalog_open(knot_catalog_t *cat)
{
	if (!knot_lmdb_is_open(&cat->db)) {
		int ret = knot_lmdb_open(&cat->db);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}
	if (!cat->txn.opened) {
		knot_lmdb_begin(&cat->db, &cat->txn, !(cat->db.env_flags & MDB_RDONLY));
	}
	if (cat->txn.ret == KNOT_EOK) {
		MDB_val key = { 8, "\x01version" };
		if (knot_lmdb_find(&cat->txn, &key, KNOT_LMDB_EXACT)) {
			if (strncmp(CATALOG_VERSION, cat->txn.cur_val.mv_data, cat->txn.cur_val.mv_size) != 0) {
				log_warning("unmatching catalog version");
			}
		} else if (!(cat->db.env_flags & MDB_RDONLY)) {
			MDB_val val = { strlen(CATALOG_VERSION), CATALOG_VERSION };
			knot_lmdb_insert(&cat->txn, &key, &val);
		}
	}
	return cat->txn.ret;
}

int knot_catalog_deinit(knot_catalog_t *cat)
{
	if (cat->txn.opened) {
		knot_lmdb_commit(&cat->txn);
	}
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
	int ret = knot_catalog_open(cat);
	if (ret != KNOT_EOK) {
		return ret;
	}
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
	if (!knot_lmdb_is_open(&cat->db)) {
		return KNOT_ENOENT;
	}

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
			free(counter);
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
		const knot_dname_t *member = knot_ptr_name(rdata);
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
	int ret = knot_catalog_open(cat);
	if (ret != KNOT_EOK) {
		return ret;
	}

	pthread_mutex_lock(&u->mutex);
	knot_catalog_foreach(cat) { // TODO possible speedup by indexing which member zones belong to a catalog zone
		const knot_dname_t *mem, *ow, *cz;
		knot_catalog_curval(cat, &mem, &ow, &cz);
		if (knot_dname_is_equal(cz, zone)) {
			ret = knot_cat_update_add(u, mem, ow, cz, true);
			if (ret != KNOT_EOK) {
				pthread_mutex_unlock(&u->mutex);
				return ret;
			}
		}
	}
	pthread_mutex_unlock(&u->mutex);
	return cat->txn.ret;
}

static void print_dname(const knot_dname_t *d)
{
	char tmp[KNOT_DNAME_TXT_MAXLEN];
	knot_dname_to_str(tmp, d, sizeof(tmp));
	printf("%s ", tmp);
}

static void print_dname3(const char *pre, const knot_dname_t *a, const knot_dname_t *b, const knot_dname_t *c, const char *suff)
{
	printf("%s ", pre);
	print_dname(a);
	print_dname(b);
	print_dname(c);
	printf("%s\n", suff);
}

void knot_cat_update_print(const char *intro, knot_catalog_t *cat, knot_cat_update_t *u)
{
	ssize_t cattot = 0, uplus = 0, uminus = 0;

	printf("Catalog (%s)\n", intro);

	if (cat != NULL) {
		int ret = knot_catalog_open(cat);
		if (ret != KNOT_EOK) {
			printf("Catalog print failed (%s)\n", knot_strerror(ret));
			return;
		}

		knot_catalog_foreach(cat) {
			const knot_dname_t *mem, *ow, *cz;
			knot_catalog_curval(cat, &mem, &ow, &cz);
			print_dname3("*", mem, ow, cz, "");
			cattot++;
		}
	}
	if (u != NULL) {
		knot_cat_it_t *it = knot_cat_it_begin(u, true);
		while (!knot_cat_it_finised(it)) {
			knot_cat_upd_val_t *val = knot_cat_it_val(it);
			print_dname3("-", val->member, val->owner, val->catzone, "");
			uminus++;
			knot_cat_it_next(it);
		}
		knot_cat_it_free(it);

		it = knot_cat_it_begin(u, false);
		while (!knot_cat_it_finised(it)) {
			knot_cat_upd_val_t *val = knot_cat_it_val(it);
			print_dname3("+", val->member, val->owner, val->catzone, val->just_reconf ? "JR" : "");
			uplus++;
			knot_cat_it_next(it);
		}
		knot_cat_it_free(it);
	}
	printf("Catalog: *%zd -%zd +%zd\n", cattot, uminus, uplus);
}
