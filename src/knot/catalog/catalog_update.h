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

#pragma once

#include "contrib/qp-trie/trie.h"
#include "knot/catalog/catalog_db.h"
#include "knot/conf/conf.h"

typedef enum {
	CAT_UPD_INVALID,   // invalid value
	CAT_UPD_ADD,       // member addition
	CAT_UPD_REM,       // member removal
	CAT_UPD_MINOR,     // owner or catzone change, uniqID preserved
	CAT_UPD_UNIQ,      // uniqID change
	CAT_UPD_PROP,      // ONLY change of properties of existing member
	CAT_UPD_MAX,       // number of options in ths enum
} catalog_upd_type_t;

typedef struct catalog_upd_val {
	knot_dname_t *member;     // name of catalog member zone
	catalog_upd_type_t type;  // what kind of update this is

	knot_dname_t *rem_owner;  // owner of PTR record being removed
	knot_dname_t *rem_catz;   // catalog zone the member being removed from
	knot_dname_t *add_owner;  // owner of PTR record being added
	knot_dname_t *add_catz;   // catalog zone the member being added to

	char *new_group;          // the desired configuration group for the member
} catalog_upd_val_t;

typedef struct {
	trie_t *upd;             // tree of catalog_upd_val_t, that gonna be changed in catalog
	int error;               // error occurred during generating of upd
	pthread_mutex_t mutex;   // lock for accessing this struct
} catalog_update_t;

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
 * \param type      CAT_UPD_REM, CAT_UPD_ADD, CAT_UPD_PROP.
 * \param group     Optional: member group property value.
 * \param group_len Length of 'group' string (if not NULL).
 * \param check_rem Check catalog DB for existing record to be removed.
 *
 * \return KNOT_E*
 */
int catalog_update_add(catalog_update_t *u, const knot_dname_t *member,
                       const knot_dname_t *owner, const knot_dname_t *catzone,
                       catalog_upd_type_t type, const char *group,
                       size_t group_len, catalog_t *check_rem);

/*!
 * \brief Read catalog update record for given member zone.
 *
 * \param u          Catalog update.
 * \param member     Member zone name.
 * \param remove     Search in remove section.
 *
 * \return Found update record for given member zone; or NULL.
 */
catalog_upd_val_t *catalog_update_get(catalog_update_t *u, const knot_dname_t *member);

/*!
 * \brief Catalog update iteration.
 */
typedef trie_it_t catalog_it_t;

inline static catalog_it_t *catalog_it_begin(catalog_update_t *u)
{
	return trie_it_begin(u->upd);
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
 * \brief Check Catalog update for conflicts with conf or other catalogs.
 *
 * \param u      Catalog update to be aligned in-place.
 * \param cat    Catalog DB to check against.
 * \param conf   Relevant configuration.
 */
void catalog_update_finalize(catalog_update_t *u, catalog_t *cat, conf_t *conf);

/*!
 * \brief Put changes from Catalog Update into persistent Catalog database.
 *
 * \param u      Catalog update to be committed.
 * \param cat    Catalog to be updated.
 *
 * \return KNOT_E*
 */
int catalog_update_commit(catalog_update_t *u, catalog_t *cat);

/*!
 * \brief Add to catalog update removals of all member zones of a single catalog zone.
 *
 * \param u      Catalog update to be updated.
 * \param cat    Catalog database to be iterated.
 * \param zone   Name of catalog zone whose members gonna be removed.
 * \param upd_count          Output: number of resulting updates to catalog database.
 *
 * \return KNOT_E*
 */
int catalog_update_del_all(catalog_update_t *u, catalog_t *cat, const knot_dname_t *zone, ssize_t *upd_count);
