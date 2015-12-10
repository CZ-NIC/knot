/*!
 * \file zonedb.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Zone database structure and API for manipulating it.
 *
 * Zone database groups several zones and provides functions for finding
 * suitable zone for a domain name, for searching in a particular zone, etc.
 *
 * \addtogroup libknot
 * @{
 */
/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "knot/zone/node.h"
#include "knot/zone/zone.h"
#include "knot/zone/contents.h"
#include "libknot/dname.h"
#include "contrib/hhash.h"

/*
 * Zone DB represents a list of managed zones.
 * Hashing should be avoided as it is expensive when only a small number of
 * zones is present (TLD case). Fortunately hhash is able to do linear scan if
 * it has only a handful of names present. Furthermore, we track the name with
 * the most labels in the database. So if we have for example a 'a.b.' in the
 * database and search for 'c.d.a.b.' we can trim the 'c.d.' and search for
 * the suffix as we now there can't be a closer match.
 */
typedef struct {
	uint16_t maxlabels;
	hhash_t *hash;
	knot_mm_t mm;
} knot_zonedb_t;

/*
 * Mapping of iterators to internal data structure.
 */
typedef hhash_iter_t knot_zonedb_iter_t;
#define knot_zonedb_iter_begin(db, it) hhash_iter_begin((db)->hash, it, true)
#define knot_zonedb_iter_finished(it) hhash_iter_finished(it)
#define knot_zonedb_iter_next(it) hhash_iter_next(it)
#define knot_zonedb_iter_val(it) *hhash_iter_val(it)

/*
 * Simple foreach() access with callback and variable number of callback params.
 */
#define knot_zonedb_foreach(db, callback, ...) \
{ \
	knot_zonedb_iter_t it; \
	knot_zonedb_iter_begin((db), &it); \
	while(!knot_zonedb_iter_finished(&it)) { \
		callback((zone_t *)knot_zonedb_iter_val(&it), ##__VA_ARGS__); \
		knot_zonedb_iter_next(&it); \
	} \
}

/*----------------------------------------------------------------------------*/

/*!
 * \brief Allocates and initializes the zone database structure.
 *
 * \return Pointer to the created zone database structure or NULL if an error
 *         occured.
 */
knot_zonedb_t *knot_zonedb_new(uint32_t size);

/*!
 * \brief Adds new zone to the database.
 *
 * \param db Zone database to store the zone.
 * \param zone Parsed zone.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EZONEIN
 */
int knot_zonedb_insert(knot_zonedb_t *db, zone_t *zone);

/*!
 * \brief Removes the given zone from the database if it exists.
 *
 * \param db Zone database to remove from.
 * \param zone_name Name of the zone to be removed.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOZONE
 */
int knot_zonedb_del(knot_zonedb_t *db, const knot_dname_t *zone_name);

/*!
 * \brief Build zone stack for faster lookup.
 */
int knot_zonedb_build_index(knot_zonedb_t *db);

/*!
 * \brief Finds zone exactly matching the given zone name.
 *
 * \param db Zone database to search in.
 * \param zone_name Domain name representing the zone name.
 *
 * \return Zone with \a zone_name being the owner of the zone apex or NULL if
 *         not found.
 */
zone_t *knot_zonedb_find(knot_zonedb_t *db, const knot_dname_t *zone_name);

/*!
 * \brief Finds zone the given domain name should belong to.
 *
 * \param db Zone database to search in.
 * \param dname Domain name to find zone for.
 *
 * \retval Zone in which the domain name should be present or NULL if no such
 *         zone is found.
 */
zone_t *knot_zonedb_find_suffix(knot_zonedb_t *db, const knot_dname_t *dname);

size_t knot_zonedb_size(const knot_zonedb_t *db);

/*!
 * \brief Destroys and deallocates the zone database structure (but not the
 *        zones within).
 *
 * \param db Zone database to be destroyed.
 */
void knot_zonedb_free(knot_zonedb_t **db);

/*!
 * \brief Destroys and deallocates the whole zone database including the zones.
 *
 * \param db Zone database to be destroyed.
 */
void knot_zonedb_deep_free(knot_zonedb_t **db);

/*! @} */
