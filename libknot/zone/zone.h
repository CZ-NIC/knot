/*!
 * \file zone.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Zone structure and API for manipulating it.
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

#ifndef _KNOT_ZONE_H_
#define _KNOT_ZONE_H_

#include <time.h>

#include "zone/node.h"
#include "dname.h"
#include "nsec3.h"
#include "zone/dname-table.h"
#include "common/tree.h"
#include "hash/cuckoo-hash-table.h"

#include "zone-tree.h"

#include "zone/zone-contents.h"

/*----------------------------------------------------------------------------*/

//typedef TREE_HEAD(avl_tree, knot_node) avl_tree_t;
//struct event_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Return values for search functions.
 *
 * Used in knot_zone_find_dname() and knot_zone_find_dname_hash().
 */
enum knot_zone_retvals {
	KNOT_ZONE_NAME_FOUND = 1,
	KNOT_ZONE_NAME_NOT_FOUND = 0
};

typedef enum knot_zone_retvals knot_zone_retvals_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Structure for holding DNS zone.
 *
 * \warning Make sure not to insert the same nodes using both the normal and
 *          NSEC3 functions. Although this will be successfull, it will produce
 *          double-free errors when destroying the zone.
 */
struct knot_zone {
	knot_dname_t *name;

	knot_zone_contents_t *contents;

	time_t version;

	/*! \todo Set when loading zone. */
	short master;

	void *data; /*!< Pointer to generic zone-related data. */
	int (*dtor)(struct knot_zone *); /*!< Data destructor. */
};

typedef struct knot_zone knot_zone_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Creates new empty DNS zone.
 *
 * \notice Zone will be created without contents.
 *
 * \param name Zone owner.
 *
 * \return The initialized zone structure or NULL if an error occured.
 */
knot_zone_t *knot_zone_new_empty(knot_dname_t *name);

/*!
 * \brief Creates new DNS zone.
 *
 * \param apex Node representing the zone apex.
 * \param node_count Number of authorative nodes in the zone.
 *
 * \return The initialized zone structure or NULL if an error occured.
 */
knot_zone_t *knot_zone_new(knot_node_t *apex, uint node_count,
                               int use_domain_table);

knot_zone_contents_t *knot_zone_get_contents(
	const knot_zone_t *zone);

const knot_zone_contents_t *knot_zone_contents(
	const knot_zone_t *zone);


time_t knot_zone_version(const knot_zone_t *zone);

void knot_zone_set_version(knot_zone_t *zone, time_t version);

short knot_zone_is_master(const knot_zone_t *zone);

void knot_zone_set_master(knot_zone_t *zone, short master);

const void *knot_zone_data(const knot_zone_t *zone);

void knot_zone_set_data(knot_zone_t *zone, void *data);

const knot_dname_t *knot_zone_name(const knot_zone_t *zone);

knot_zone_contents_t *knot_zone_switch_contents(knot_zone_t *zone,
                                          knot_zone_contents_t *new_contents);

/*!
 * \brief Correctly deallocates the zone structure, without deleting its nodes.
 *
 * Also sets the given pointer to NULL.
 *
 * \param zone Zone to be freed.
 */
void knot_zone_free(knot_zone_t **zone);

/*!
 * \brief Correctly deallocates the zone structure and all nodes within.
 *
 * Also sets the given pointer to NULL.
 *
 * \param zone Zone to be freed.
 * \param free_rdata_dnames Set to <> 0 if you want to delete ALL domain names
 *                          present in RDATA. Set to 0 otherwise. (See
 *                          knot_rdata_deep_free().)
 */
void knot_zone_deep_free(knot_zone_t **zone, int destroy_dname_table);

#endif

/*! @} */
