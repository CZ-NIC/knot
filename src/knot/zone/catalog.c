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
#define CATALOG_ZONE_VERSION "2" // must be just one char long

const MDB_val catalog_iter_prefix = { 1, "" };

static bool check_zone_version(const zone_contents_t *zone)
{
	size_t zone_size = knot_dname_size(zone->apex->owner);
	knot_dname_t sub[zone_size + 8];
	memcpy(sub, "\x07""version", 8);
	memcpy(sub + 8, zone->apex->owner, zone_size);

	const zone_node_t *ver_node = zone_contents_find_node(zone, sub);
	knot_rdataset_t *ver_rr = node_rdataset(ver_node, KNOT_RRTYPE_TXT);
	if (ver_rr == NULL) {
		return false;
	}

	knot_rdata_t *rd = ver_rr->rdata;
	for (int i = 0; i < ver_rr->count; i++) {
		if (rd->len == 2 && rd->data[1] == CATALOG_ZONE_VERSION[0]) {
			return true;
		}
		rd = knot_rdataset_next(rd);
	}
	return false;
}

void catalog_init(catalog_t *cat, const char *path, size_t mapsize)
{
	knot_lmdb_init(&cat->db, path, mapsize, 0, NULL);
}

int catalog_open(catalog_t *cat)
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
			if (strncmp(CATALOG_VERSION, cat->txn.cur_val.mv_data,
			            cat->txn.cur_val.mv_size) != 0) {
				log_warning("unmatching catalog version");
			}
		} else if (!(cat->db.env_flags & MDB_RDONLY)) {
			MDB_val val = { strlen(CATALOG_VERSION), CATALOG_VERSION };
			knot_lmdb_insert(&cat->txn, &key, &val);
		}
	}
	return cat->txn.ret;
}

int catalog_deinit(catalog_t *cat)
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

int catalog_add(catalog_t *cat, const knot_dname_t *member,
                const knot_dname_t *owner, const knot_dname_t *catzone)
{
	int ret = catalog_open(cat);
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

int catalog_del(catalog_t *cat, const knot_dname_t *member)
{
	MDB_val key = knot_lmdb_make_key("BN", 0, member);
	knot_lmdb_del_prefix(&cat->txn, &key); // deletes one record
	free(key.mv_data);
	return cat->txn.ret;
}

void catalog_curval(catalog_t *cat, const knot_dname_t **member,
                    const knot_dname_t **owner, const knot_dname_t **catzone)
{
	uint8_t zero, shift;
	if (member != NULL) {
		knot_lmdb_unmake_key(cat->txn.cur_key.mv_data, cat->txn.cur_key.mv_size,
		                     "BN", &zero, member);
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

int catalog_get_zone(catalog_t *cat, const knot_dname_t *member,
                     const knot_dname_t **catzone)
{
	if (!knot_lmdb_is_open(&cat->db)) {
		return KNOT_ENOENT;
	}

	MDB_val key = knot_lmdb_make_key("BN", 0, member);
	if (knot_lmdb_find(&cat->txn, &key, KNOT_LMDB_EXACT)) {
		catalog_curval(cat, NULL, NULL, catzone);
		free(key.mv_data);
		return KNOT_EOK;
	}
	free(key.mv_data);
	return MIN(cat->txn.ret, KNOT_ENOENT);
}

int catalog_get_zone_threadsafe(catalog_t *cat, const knot_dname_t *member,
                                knot_dname_t **catzone)
{
	if (!knot_lmdb_is_open(&cat->db)) {
		return KNOT_ENOENT;
	}

	MDB_val key = knot_lmdb_make_key("BN", 0, member), val = { 0 };
	int ret = knot_lmdb_find_threadsafe(&cat->txn, &key, &val, KNOT_LMDB_EXACT);
	if (ret == KNOT_EOK) {
		uint8_t zero, shift;
		const knot_dname_t *ow = NULL;
		knot_lmdb_unmake_key(val.mv_data, val.mv_size, "BBN", &zero, &shift, &ow);
		*catzone = knot_dname_copy(ow + shift, NULL);
		if (*catzone == NULL) {
			ret = KNOT_ENOMEM;
		}
		free(val.mv_data);
	}
	free(key.mv_data);
	return ret;
}

catalog_find_res_t catalog_find(catalog_t *cat, const knot_dname_t *member,
                                const knot_dname_t *owner, const knot_dname_t *catzone)
{
	MDB_val key = knot_lmdb_make_key("BN", 0, member);
	int ret = MEMBER_NONE;
	if (knot_lmdb_find(&cat->txn, &key, KNOT_LMDB_EXACT)) {
		const knot_dname_t *ow, *cz;
		catalog_curval(cat, NULL, &ow, &cz);
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

int catalog_update_init(catalog_update_t *u)
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

void catalog_update_clear(catalog_update_t *u)
{
	trie_apply(u->add, freecb, NULL);
	trie_clear(u->add);
	trie_apply(u->rem, freecb, NULL);
	trie_clear(u->rem);
}

void catalog_update_deinit(catalog_update_t *u)
{
	pthread_mutex_destroy(&u->mutex);
	trie_free(u->add);
	trie_free(u->rem);
}

int catalog_update_add(catalog_update_t *u, const knot_dname_t *member,
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
		catalog_upd_val_t *counter = *found;
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

	catalog_upd_val_t *val = malloc(sizeof(*val) + member_size + owner_size);
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

catalog_upd_val_t *catalog_update_get(catalog_update_t *u, const knot_dname_t *member, bool remove)
{
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(member, lf_storage);

	trie_val_t *found = trie_get_try(remove ? u->rem : u->add, lf + 1, lf[0]);
	return found == NULL ? NULL : *(catalog_upd_val_t **)found;
}

typedef struct {
	catalog_update_t *u;
	const knot_dname_t *apex;
	bool remove;
	catalog_t *check;
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
		    catalog_find(ctx->check, member, node->owner, ctx->apex) != MEMBER_EXACT) {
			rdata = knot_rdataset_next(rdata);
			continue;
		}
		ret = catalog_update_add(ctx->u, member, node->owner, ctx->apex, ctx->remove);
		rdata = knot_rdataset_next(rdata);
	}
	return ret;
}

int catalog_update_from_zone(catalog_update_t *u, struct zone_contents *zone,
                             bool remove, bool check_ver, catalog_t *check)
{
	if (check_ver && !check_zone_version(zone)) {
		return KNOT_EZONEINVAL;
	}

	size_t zone_size = knot_dname_size(zone->apex->owner);
	knot_dname_t sub[zone_size + 6];
	memcpy(sub, "\x05""zones", 6);
	memcpy(sub + 6, zone->apex->owner, zone_size);

	if (zone_contents_find_node(zone, sub) == NULL) {
		return KNOT_EOK;
	}

	cat_upd_ctx_t ctx = { u, zone->apex->owner, remove, check };
	pthread_mutex_lock(&u->mutex);
	int ret = zone_tree_sub_apply(zone->nodes, sub, false, cat_update_add_node, &ctx);
	pthread_mutex_unlock(&u->mutex);
	return ret;
}

int catalog_update_del_all(catalog_update_t *u, catalog_t *cat, const knot_dname_t *zone)
{
	int ret = catalog_open(cat);
	if (ret != KNOT_EOK) {
		return ret;
	}

	pthread_mutex_lock(&u->mutex);
	catalog_foreach(cat) { // TODO possible speedup by indexing which member zones belong to a catalog zone
		const knot_dname_t *mem, *ow, *cz;
		catalog_curval(cat, &mem, &ow, &cz);
		if (knot_dname_is_equal(cz, zone)) {
			ret = catalog_update_add(u, mem, ow, cz, true);
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

void catalog_update_print(const char *intro, catalog_t *cat, catalog_update_t *u)
{
	ssize_t cattot = 0, uplus = 0, uminus = 0;

	printf("Catalog (%s)\n", intro);

	if (cat != NULL) {
		int ret = catalog_open(cat);
		if (ret != KNOT_EOK) {
			printf("Catalog print failed (%s)\n", knot_strerror(ret));
			return;
		}

		catalog_foreach(cat) {
			const knot_dname_t *mem, *ow, *cz;
			catalog_curval(cat, &mem, &ow, &cz);
			print_dname3("*", mem, ow, cz, "");
			cattot++;
		}
	}
	if (u != NULL) {
		catalog_it_t *it = catalog_it_begin(u, true);
		while (!catalog_it_finished(it)) {
			catalog_upd_val_t *val = catalog_it_val(it);
			print_dname3("-", val->member, val->owner, val->catzone, "");
			uminus++;
			catalog_it_next(it);
		}
		catalog_it_free(it);

		it = catalog_it_begin(u, false);
		while (!catalog_it_finished(it)) {
			catalog_upd_val_t *val = catalog_it_val(it);
			print_dname3("+", val->member, val->owner, val->catzone, val->just_reconf ? "JR" : "");
			uplus++;
			catalog_it_next(it);
		}
		catalog_it_free(it);
	}
	printf("Catalog: *%zd -%zd +%zd\n", cattot, uminus, uplus);
}
