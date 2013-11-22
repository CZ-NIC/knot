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

#ifndef _KNOT_ZONEDB_H_
#define _KNOT_ZONEDB_H_

#include "libknot/zone/zone.h"
#include "libknot/zone/node.h"
#include "libknot/dname.h"

/*
 * Zone DB represents a list of managed zones.
 * Hashing should be avoided as it is expensive when only a small number of
 * zones is present (TLD case). Linear run-length algorithms or worse should
 * be avoided as well, as the number of zones may be large.
 *
 * Use of string-based algorithms for suffix search is viable, but would require
 * transformation each time a name is searched. That again would be a
 * constant cost even if the number of zones would be small.
 *
 * Zone database structure is a stack of zones grouped by label count in
 * descending order (root label not counted), therefore first match is the longest.
 * Each stack level is sorted for convenient binary search.
 * example:
 *  {3 labels, 2 items} => [ 'a.b.c', 'b.b.c' ]
 *  {2 labels, 1 items} => [ 'x.z' ]
 *  {1 labels, 2 items} => [ 'y', 'w' ]
 *
 * Stack is built on top of the sorted array of zones for direct access and
 * less memory requirements.
 */
typedef struct {
	unsigned labels;
	unsigned count;
	knot_zone_t** array;
} knot_zonedb_stack_t;

typedef struct {
	unsigned count, reserved;
	knot_zone_t **array;
	unsigned stack_height;
	knot_zonedb_stack_t stack[KNOT_DNAME_MAXLABELS];
} knot_zonedb_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Allocates and initializes the zone database structure.
 *
 * \return Pointer to the created zone database structure or NULL if an error
 *         occured.
 */
knot_zonedb_t *knot_zonedb_new(unsigned size);

/*!
 * \brief Adds new zone to the database.
 *
 * \param db Zone database to store the zone.
 * \param zone Parsed zone.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EZONEIN
 */
int knot_zonedb_add_zone(knot_zonedb_t *db, knot_zone_t *zone);

/*!
 * \brief Removes the given zone from the database if it exists.
 *
 * \param db Zone database to remove from.
 * \param zone_name Name of the zone to be removed.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOZONE
 */
knot_zone_t * knot_zonedb_remove_zone(knot_zonedb_t *db,
                                      const knot_dname_t *zone_name);

/*!
 * \brief Build zone stack for faster lookup.
 *
 * Zone stack structure is described in the knot_zonedb_t struct.
 *
 * \param db Zone database.
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 * \retval KNOT_EINVAL
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
knot_zone_t *knot_zonedb_find_zone(knot_zonedb_t *db,
                                   const knot_dname_t *zone_name);


/*!
 * \brief Finds zone the given domain name should belong to.
 *
 * \param db Zone database to search in.
 * \param dname Domain name to find zone for.
 *
 * \retval Zone in which the domain name should be present or NULL if no such
 *         zone is found.
 */
knot_zone_t *knot_zonedb_find_zone_for_name(knot_zonedb_t *db,
                                            const knot_dname_t *dname);

knot_zone_contents_t *knot_zonedb_expire_zone(knot_zonedb_t *db,
                                              const knot_dname_t *zone_name);

size_t knot_zonedb_zone_count(const knot_zonedb_t *db);
const knot_zone_t **knot_zonedb_zones(const knot_zonedb_t *db);

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

/*----------------------------------------------------------------------------*/

#endif /* _KNOT_ZONEDB_H_ */

/*! @} */
