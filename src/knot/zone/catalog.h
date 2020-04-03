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

#pragma once

#include <pthread.h>

#include "libknot/dname.h"
#include "libknot/error.h"

#include "contrib/qp-trie/trie.h"
#include "knot/journal/knot_lmdb.h"
#include "libknot/rrset.h"

typedef struct knot_catalog {
	knot_lmdb_db_t db;
	knot_lmdb_txn_t txn; // RW transaction open all the time
} knot_catalog_t;

typedef enum {
	MEMBER_NONE,   // this member zone is not in any catalog
	MEMBER_EXACT,  // this member zone precisely matches lookup
	MEMBER_ZONE,   // this member zone is in different catalog
	MEMBER_OWNER,  // this member zone is in same catalog with diferent owner
	MEMBER_ERROR,  // find error code in cat->txn.ret
} knot_cat_find_res_t;

typedef struct {
	trie_t *rem;
	trie_t *add;
	pthread_mutex_t mutex;
} knot_cat_update_t;

typedef struct {
	knot_dname_t *member;
	knot_dname_t *owner;
	knot_dname_t *catzone;
	bool just_reconf;
} knot_cat_upd_val_t;

extern const MDB_val knot_catalog_iter_prefix;

void knot_catalog_init(knot_catalog_t *cat, const char *path, size_t mapsize);

int knot_catalog_open(knot_catalog_t *cat);

int knot_catalog_deinit(knot_catalog_t *cat);

int knot_catalog_add(knot_catalog_t *cat, const knot_dname_t *member,
                     const knot_dname_t *owner, const knot_dname_t *catzone);

inline static int knot_catalog_add2(knot_catalog_t *cat, const knot_cat_upd_val_t *val)
{
	return knot_catalog_add(cat, val->member, val->owner, val->catzone);
}

int knot_catalog_del(knot_catalog_t *cat, const knot_dname_t *member);

inline static int knot_catalog_del2(knot_catalog_t *cat, const knot_cat_upd_val_t *val)
{
	assert(!val->just_reconf); // just re-add in this case
	return knot_catalog_del(cat, val->member);
}

#define knot_catalog_foreach(cat) knot_lmdb_foreach(&(cat)->txn, (MDB_val *)&knot_catalog_iter_prefix)

void knot_catalog_curval(knot_catalog_t *cat, const knot_dname_t **member,
                         const knot_dname_t **owner, const knot_dname_t **catzone);

int knot_catalog_get_catzone(knot_catalog_t *cat, const knot_dname_t *member,
                             const knot_dname_t **catzone);

knot_cat_find_res_t knot_catalog_find(knot_catalog_t *cat, const knot_dname_t *member,
                                      const knot_dname_t *owner, const knot_dname_t *catzone);

int knot_cat_update_init(knot_cat_update_t *u);

void knot_cat_update_clear(knot_cat_update_t *u);

void knot_cat_update_deinit(knot_cat_update_t *u);

int knot_cat_update_add(knot_cat_update_t *u, const knot_dname_t *member,
                        const knot_dname_t *owner, const knot_dname_t *catzone,
                        bool remove);

knot_cat_upd_val_t *knot_cat_update_get(knot_cat_update_t *u, const knot_dname_t *member, bool remove);

struct zone_contents;

int knot_cat_update_from_zone(knot_cat_update_t *u, struct zone_contents *zone,
                              bool remove, knot_catalog_t *check);

int knot_cat_update_del_all(knot_cat_update_t *u, knot_catalog_t *cat, const knot_dname_t *zone);

typedef trie_it_t knot_cat_it_t;

inline static knot_cat_it_t *knot_cat_it_begin(knot_cat_update_t *u, bool remove)
{
	return trie_it_begin(remove ? u->rem : u->add);
}

inline static knot_cat_upd_val_t *knot_cat_it_val(knot_cat_it_t *it)
{
	return *(knot_cat_upd_val_t **)trie_it_val(it);
}

inline static bool knot_cat_it_finised(knot_cat_it_t *it)
{
	return it == NULL || trie_it_finished(it);
}

#define knot_cat_it_next trie_it_next
#define knot_cat_it_free trie_it_free

void knot_cat_update_print(const char *intro, knot_catalog_t *cat, knot_cat_update_t *u);
