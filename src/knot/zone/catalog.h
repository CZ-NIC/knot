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

#include "libknot/libknot.h"
#include "contrib/qp-trie/trie.h"
#include "knot/journal/knot_lmdb.h"

typedef struct catalog {
	knot_lmdb_db_t db;
	knot_lmdb_txn_t txn; // RW transaction open all the time
} catalog_t;

typedef enum {
	MEMBER_NONE,   // this member zone is not in any catalog
	MEMBER_EXACT,  // this member zone precisely matches lookup
	MEMBER_ZONE,   // this member zone is in different catalog
	MEMBER_OWNER,  // this member zone is in same catalog with diferent owner
	MEMBER_ERROR,  // find error code in cat->txn.ret
} catalog_find_res_t;

typedef struct {
	trie_t *rem;
	trie_t *add;
	pthread_mutex_t mutex;
} catalog_update_t;

typedef struct {
	knot_dname_t *member;
	knot_dname_t *owner;
	knot_dname_t *catzone;
	bool just_reconf;
} catalog_upd_val_t;

extern const MDB_val catalog_iter_prefix;

void catalog_init(catalog_t *cat, const char *path, size_t mapsize);

int catalog_open(catalog_t *cat);

int catalog_deinit(catalog_t *cat);

int catalog_add(catalog_t *cat, const knot_dname_t *member,
                const knot_dname_t *owner, const knot_dname_t *catzone);

inline static int catalog_add2(catalog_t *cat, const catalog_upd_val_t *val)
{
	return catalog_add(cat, val->member, val->owner, val->catzone);
}

int catalog_del(catalog_t *cat, const knot_dname_t *member);

inline static int catalog_del2(catalog_t *cat, const catalog_upd_val_t *val)
{
	assert(!val->just_reconf); // just re-add in this case
	return catalog_del(cat, val->member);
}

#define catalog_foreach(cat) knot_lmdb_foreach(&(cat)->txn, (MDB_val *)&catalog_iter_prefix)

void catalog_curval(catalog_t *cat, const knot_dname_t **member,
                    const knot_dname_t **owner, const knot_dname_t **catzone);

int catalog_get_zone(catalog_t *cat, const knot_dname_t *member,
                     const knot_dname_t **catzone);

int catalog_get_zone_threadsafe(catalog_t *cat, const knot_dname_t *member,
                                knot_dname_t **catzone);

catalog_find_res_t catalog_find(catalog_t *cat, const knot_dname_t *member,
                                const knot_dname_t *owner, const knot_dname_t *catzone);

int catalog_update_init(catalog_update_t *u);

void catalog_update_clear(catalog_update_t *u);

void catalog_update_deinit(catalog_update_t *u);

int catalog_update_add(catalog_update_t *u, const knot_dname_t *member,
                       const knot_dname_t *owner, const knot_dname_t *catzone,
                       bool remove);

catalog_upd_val_t *catalog_update_get(catalog_update_t *u, const knot_dname_t *member, bool remove);

struct zone_contents;

int catalog_update_from_zone(catalog_update_t *u, struct zone_contents *zone,
                             bool remove, bool check_ver, catalog_t *check);

int catalog_update_del_all(catalog_update_t *u, catalog_t *cat, const knot_dname_t *zone);

typedef trie_it_t catalog_it_t;

inline static catalog_it_t *catalog_it_begin(catalog_update_t *u, bool remove)
{
	return trie_it_begin(remove ? u->rem : u->add);
}

inline static catalog_upd_val_t *catalog_it_val(catalog_it_t *it)
{
	return *(catalog_upd_val_t **)trie_it_val(it);
}

inline static bool catalog_it_finished(catalog_it_t *it)
{
	return it == NULL || trie_it_finished(it);
}

#define catalog_it_next trie_it_next
#define catalog_it_free trie_it_free

void catalog_print(catalog_t *cat);
void catalog_update_print(catalog_update_t *u);
