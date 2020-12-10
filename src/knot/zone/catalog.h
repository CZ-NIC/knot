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
	knot_lmdb_txn_t *ro_txn; // persistent RO transaction
	knot_lmdb_txn_t *rw_txn; // temporary RW transaction

	// private
	knot_lmdb_txn_t *old_ro_txn;
} catalog_t;

typedef enum {
	MEMBER_NONE,   // this member zone is not in any catalog
	MEMBER_EXACT,  // this member zone precisely matches lookup
	MEMBER_ZONE,   // this member zone is in different catalog
	MEMBER_OWNER,  // this member zone is in same catalog with diferent owner
	MEMBER_ERROR,  // find error code in cat->txn.ret
} catalog_find_res_t;

typedef struct {
	trie_t *rem;             // tree of catalog_upd_val_t, that gonna be removed from catalog
	trie_t *add;             // tree of catalog_upd_val_t, that gonna be added to catalog
	int error;               // error occured during generating of upd
	pthread_mutex_t mutex;   // lock for accessing this struct
} catalog_update_t;

typedef struct {
	knot_dname_t *member;     // name of catalog member zone
	knot_dname_t *owner;      // the owner of PTR record defining the member zone
	knot_dname_t *catzone;    // the catalog zone the PTR is in
	bool just_reconf;         // this addition is of an existing member zone, which however shall be reset (purged)
} catalog_upd_val_t;

extern const MDB_val catalog_iter_prefix;

/*!
 * \brief Generate owner name for catalog PTR record.
 *
 * \param member        Name of the member zone respective to the PTR record.
 * \param catzone       Catalog zone name to contain the PTR.
 * \param member_time   Timestamp of member zone addition.
 *
 * \return Owner name or NULL on error (e.g. ENOMEM, too long result...).
 *
 * \note Don't forget to free the return value later.
 */
knot_dname_t *catalog_member_owner(const knot_dname_t *member,
                                   const knot_dname_t *catzone,
                                   time_t member_time);

/*!
 * \brief Initialize catalog structure.
 *
 * \param cat        Catalog structure.
 * \param path       Path to LMDB for catalog.
 * \param mapsize    Mapsize of the LMDB.
 */
void catalog_init(catalog_t *cat, const char *path, size_t mapsize);

/*!
 * \brief Open the catalog LMDB, create it if not exists.
 *
 * \param cat   Catlog to be opened.
 *
 * \return KNOT_E*
 */
int catalog_open(catalog_t *cat);

/*!
 * \brief Start a temporary RW transaction in the catalog.
 *
 * \param cat   Catalog in question.
 *
 * \return KNOT_E*
 */
int catalog_begin(catalog_t *cat);

/*!
 * \brief End using the temporary RW txn, refresh the persistent RO txn.
 *
 * \param cat   Catalog in question.
 *
 * \return KNOT_E*
 */
int catalog_commit(catalog_t *cat);

/*!
 * \brief Free up old txns.
 *
 * \note This must be called after catalog_commit() with a delay of synchronnize_rcu().
 *
 * \param cat   Catalog.
 */
void catalog_commit_cleanup(catalog_t *cat);

/*!
 * \brief Close the catalog and de-init the structure.
 *
 * \param cat   Catalog to be closed.
 *
 * \return KNOT_E*
 */
int catalog_deinit(catalog_t *cat);

/*!
 * \brief Add a member zone to the catalog database.
 *
 * \param cat       Catalog to be augmented.
 * \param member    Member zone name.
 * \param owner     Owner of the PTR record in catalog zone, respective to the member zone.
 * \param catzone   Name of the catalog zone whose it's the member.
 *
 * \return KNOT_E*
 */
int catalog_add(catalog_t *cat, const knot_dname_t *member,
                const knot_dname_t *owner, const knot_dname_t *catzone);

inline static int catalog_add2(catalog_t *cat, const catalog_upd_val_t *val)
{
	return catalog_add(cat, val->member, val->owner, val->catzone);
}

/*!
 * \brief Delete a member zone from the catalog database.
 *
 * \param cat       Catalog to be removed from.
 * \param member    Member zone to be removed.
 *
 * \return KNOT_E*
 */
int catalog_del(catalog_t *cat, const knot_dname_t *member);

inline static int catalog_del2(catalog_t *cat, const catalog_upd_val_t *val)
{
	assert(!val->just_reconf); // just re-add in this case
	return catalog_del(cat, val->member);
}

#define catalog_foreach(cat) knot_lmdb_foreach((cat)->ro_txn, (MDB_val *)&catalog_iter_prefix)

/*!
 * \brief Deserialize a value in catalog database.
 *
 * \param cat       Catalog with cat->txn->cur_val to be deserialized.
 * \param member    Output: member zone.
 * \param owner     Output: PTR owner.
 * \param catzone   Output: catalog zone.
 */
void catalog_curval(catalog_t *cat, const knot_dname_t **member,
                    const knot_dname_t **owner, const knot_dname_t **catzone);

/*!
 * \brief Get the catalog zone for known member zone.
 *
 * \param cat        Catalog database.
 * \param member     Member zone name.
 * \param catzone    Catalog zone holding the member zone.
 *
 * \return KNOT_E*
 */
int catalog_get_zone(catalog_t *cat, const knot_dname_t *member,
                     const knot_dname_t **catzone);

/*!
 * \brief Get the catalog zone for known member zone.
 *
 * \note This function is safe for multithreaded operation over shared LMDB transaction.
 *
 * \param cat        Catalog database.
 * \param member     Member zone name.
 * \param catzone    Catalog zone holding the member zone.
 *
 * \return KNOT_E*
 */
int catalog_get_zone_threadsafe(catalog_t *cat, const knot_dname_t *member,
                                knot_dname_storage_t catzone);

/*!
 * \brief Find specific member record in catalog database.
 *
 * \param cat        Catalog database.
 * \param member     Member zone to be searched for.
 * \param owner      Owner to be searched/verified.
 * \param catzone    Catalog zone to be searched/verified.
 *
 * \return see catalog_find_res_t
 */
catalog_find_res_t catalog_find(catalog_t *cat, const knot_dname_t *member,
                                const knot_dname_t *owner, const knot_dname_t *catzone);

/*!
 * \brief Copy records from one catalog database to other.
 *
 * \param from            Catalog DB to copy from.
 * \param to              Catalog db to copy to.
 * \param zone_only       Optional: copy only records for this catalog zone.
 * \param read_rw_txn     Use RW txn for read operations.
 *
 * \return KNOT_E*
 */
int catalog_copy(knot_lmdb_db_t *from, knot_lmdb_db_t *to,
                 const knot_dname_t *zone_only, bool read_rw_txn);

/*!
 * \brief Initialize catalog update structure.
 *
 * \param u   Catalog update to be initialized.
 *
 * \return KNOT_EOK, KNOT_ENOMEM
 */
int catalog_update_init(catalog_update_t *u);
catalog_update_t *catalog_update_new(void);

/*!
 * \brief Clear contents of catalog update structure.
 *
 * \param u   Catalog update structure to be cleared.
 */
void catalog_update_clear(catalog_update_t *u);

/*!
 * \brief Free catalog update structure.
 *
 * \param u   Catalog update structure.
 */
void catalog_update_deinit(catalog_update_t *u);
void catalog_update_free(catalog_update_t *u);

/*!
 * \brief Add a new record to catalog update structure.
 *
 * \param u         Catalog update.
 * \param member    Member zone name to be added.
 * \param owner     Owner of respective PTR record.
 * \param catzone   Catalog zone holding the member.
 * \param remove    Add a removal of such record.
 *
 * \return KNOT_E*
 */
int catalog_update_add(catalog_update_t *u, const knot_dname_t *member,
                       const knot_dname_t *owner, const knot_dname_t *catzone,
                       bool remove);

/*!
 * \brief Read catalog update record for given member zone.
 *
 * \param u          Catalog update.
 * \param member     Member zone name.
 * \param remove     Search in remove section.
 *
 * \return Found update record for given member zone; or NULL.
 */
catalog_upd_val_t *catalog_update_get(catalog_update_t *u, const knot_dname_t *member, bool remove);

struct zone_contents;

/*!
 * \brief Iterate over PTR records in given zone contents and add members to catalog update.
 *
 * \param u            Catalog update to be updated.
 * \param zone         Zone contents to be searched for member PTR records.
 * \param remove       Add removals of found member zones.
 * \param check_ver    Do check catalog zone version record first.
 * \param check        Optional: existing catalog database to be checked for existence of such record (useful for removals).
 *
 * \return KNOT_E*
 */
int catalog_update_from_zone(catalog_update_t *u, struct zone_contents *zone,
                             bool remove, bool check_ver, catalog_t *check);

/*!
 * \brief Generate catalog zone contents from (full) catalog update.
 *
 * \param u           Catalog update to read.
 * \param catzone     Catalog zone name.
 * \param soa_serial  SOA serial of the generated zone.
 *
 * \return Catalog zone contents, or NULL if ENOMEM.
 */
struct zone_contents *catalog_update_to_zone(catalog_update_t *u, const knot_dname_t *catzone,
                                             uint32_t soa_serial);

struct zone_update;

/*!
 * \brief Incrementally update catalog zone from catalog update.
 *
 * \param u    Catalog update to read.
 * \param zu   Zone update to be updated.
 *
 * \return KNOT_E*
 */
int catalog_update_to_update(catalog_update_t *u, struct zone_update *zu);

/*!
 * \brief Add to catalog update removals of all member zones of a single catalog zone.
 *
 * \param u      Catalog updat to be updated.
 * \param cat    Catalog database to be iterated.
 * \param zone   Name of catalog zone whose members gonna be removed.
 *
 * \return KNOT_E*
 */
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

/*!
 * \brief Print to stdout whole contents of catalog database (for human).
 *
 * \param cat   Catalog database to be printed.
 */
void catalog_print(catalog_t *cat);

/*!
 * \brief Print to stdout whole contents of catalog update (for human).
 *
 * \param u   Catalog update to be printed.
 */
void catalog_update_print(catalog_update_t *u);
