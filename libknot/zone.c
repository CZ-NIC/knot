/*  Copyright (C) 2011 CZ.NIC Labs

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

#include <config.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <urcu.h>

#include "common.h"
#include "zone.h"
#include "node.h"
#include "dname.h"
#include "consts.h"
#include "descriptor.h"
#include "nsec3.h"
#include "error.h"
#include "debug.h"
#include "utils.h"
#include "common/tree.h"
#include "common/base32hex.h"
#include "hash/cuckoo-hash-table.h"
#include "zone-contents.h"

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_zone_t *knot_zone_new(knot_node_t *apex, uint node_count,
                               int use_domain_table)
{
	debug_knot_zone("Creating new zone!\n");
	if (apex == NULL) {
		return NULL;
	}

	knot_zone_t *zone = (knot_zone_t *)calloc(1, sizeof(knot_zone_t));
	if (zone == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	// save the zone name
	debug_knot_zone("Copying zone name.\n");
	zone->name = knot_dname_deep_copy(knot_node_owner(apex));
	if (zone->name == NULL) {
		ERR_ALLOC_FAILED;
		free(zone);
		return NULL;
	}

	debug_knot_zone("Creating zone contents.\n");
	zone->contents = knot_zone_contents_new(apex, node_count,
	                                          use_domain_table, zone);
	if (zone->contents == NULL) {
		knot_dname_release(zone->name);
		free(zone);
		return NULL;
	}

	debug_knot_zone("Initializing zone data.\n");
	/* Initialize data. */
	zone->data = 0;
	zone->dtor = 0;

	return zone;
}

/*----------------------------------------------------------------------------*/

knot_zone_contents_t *knot_zone_get_contents(
	const knot_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return rcu_dereference(zone->contents);
}

/*----------------------------------------------------------------------------*/

const knot_zone_contents_t *knot_zone_contents(
	const knot_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return rcu_dereference(zone->contents);
}

/*----------------------------------------------------------------------------*/

time_t knot_zone_version(const knot_zone_t *zone)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	return zone->version;
}

/*----------------------------------------------------------------------------*/

void knot_zone_set_version(knot_zone_t *zone, time_t version)
{
	if (zone == NULL) {
		return;
	}

	zone->version = version;
}

/*----------------------------------------------------------------------------*/

const void *knot_zone_data(const knot_zone_t *zone)
{
	return zone->data;
}

/*----------------------------------------------------------------------------*/

void knot_zone_set_data(knot_zone_t *zone, void *data)
{
	zone->data = data;
}

/*----------------------------------------------------------------------------*/

knot_zone_contents_t *knot_zone_switch_contents(knot_zone_t *zone,
                                           knot_zone_contents_t *new_contents)
{
	if (zone == NULL) {
		return NULL;
	}

	knot_zone_contents_t *old_contents =
		rcu_xchg_pointer(&zone->contents, new_contents);
	return old_contents;
}

/*----------------------------------------------------------------------------*/

void knot_zone_free(knot_zone_t **zone)
{
	if (zone == NULL || *zone == NULL) {
		return;
	}

	debug_knot_zone("zone_free().\n");

	if ((*zone)->contents && (*zone)->contents->generation != 0) {
		// zone is in the middle of an update, report
		debug_knot_zone("Destroying zone that is in the middle of an "
		                  "update.\n");
	}

	knot_dname_release((*zone)->name);

	/* Call zone data destructor if exists. */
	if ((*zone)->dtor) {
		(*zone)->dtor(*zone);
	}

	knot_zone_contents_free(&(*zone)->contents);
	free(*zone);
	*zone = NULL;

	debug_knot_zone("Done.\n");
}

/*----------------------------------------------------------------------------*/

void knot_zone_deep_free(knot_zone_t **zone, int free_rdata_dnames)
{
	if (zone == NULL || *zone == NULL) {
		return;
	}

	if ((*zone)->contents->generation != 0) {
		// zone is in the middle of an update, report
		debug_knot_zone("Destroying zone that is in the middle of an "
		                  "update.\n");
	}

DEBUG_KNOT_ZONE(
	char *name = knot_dname_to_str((*zone)->name);
	debug_knot_zone("Destroying zone %p, name: %s.\n", *zone, name);
	free(name);
);

	knot_dname_release((*zone)->name);

	/* Call zone data destructor if exists. */
	if ((*zone)->dtor) {
		(*zone)->dtor(*zone);
	}

	knot_zone_contents_deep_free(&(*zone)->contents);
	free(*zone);
	*zone = NULL;
}
