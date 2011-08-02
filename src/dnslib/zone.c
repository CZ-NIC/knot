#include <config.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <urcu.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/zone.h"
#include "dnslib/node.h"
#include "dnslib/dname.h"
#include "dnslib/consts.h"
#include "dnslib/descriptor.h"
#include "dnslib/nsec3.h"
#include "dnslib/error.h"
#include "dnslib/debug.h"
#include "dnslib/utils.h"
#include "common/tree.h"
#include "common/base32hex.h"
#include "dnslib/hash/cuckoo-hash-table.h"
#include "dnslib/zone-contents.h"

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
/* Zone contents functions. TODO: remove                                      */
/*----------------------------------------------------------------------------*/

int knot_zone_add_node(knot_zone_t *zone, knot_node_t *node,
                         int create_parents, int use_domain_table)
{
	if (zone == NULL || node == NULL) {
		return KNOT_EBADARG;
	}

	knot_node_set_zone(node, zone);

	return knot_zone_contents_add_node(zone->contents, node,
	                                     create_parents, 0,
	                                     use_domain_table);
}

/*----------------------------------------------------------------------------*/

int knot_zone_add_nsec3_node(knot_zone_t *zone, knot_node_t *node,
                               int create_parents, int use_domain_table)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	return knot_zone_contents_add_nsec3_node(zone->contents, node,
	                                           create_parents, 0,
	                                           use_domain_table);
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_zone_get_node(const knot_zone_t *zone,
                                    const knot_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return knot_zone_contents_get_node(zone->contents, name);
}

/*----------------------------------------------------------------------------*/

knot_node_t *knot_zone_get_nsec3_node(const knot_zone_t *zone,
                                          const knot_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return knot_zone_contents_get_nsec3_node(zone->contents, name);
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_zone_find_node(const knot_zone_t *zone,
                                           const knot_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return knot_zone_contents_find_node(zone->contents, name);
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_zone_find_nsec3_node(const knot_zone_t *zone,
                                                 const knot_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return knot_zone_contents_find_nsec3_node(zone->contents, name);
}

/*----------------------------------------------------------------------------*/

const knot_node_t *knot_zone_apex(const knot_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return knot_zone_contents_apex(zone->contents);
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_apply_postorder(knot_zone_t *zone,
                              void (*function)(knot_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	return knot_zone_contents_tree_apply_postorder(zone->contents,
	                                                 function, data);
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_apply_inorder(knot_zone_t *zone,
                              void (*function)(knot_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	return knot_zone_contents_tree_apply_inorder(zone->contents,
	                                               function, data);
}

/*----------------------------------------------------------------------------*/

int knot_zone_tree_apply_inorder_reverse(knot_zone_t *zone,
                              void (*function)(knot_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	return knot_zone_contents_tree_apply_inorder_reverse(zone->contents,
	                                                       function, data);
}

/*----------------------------------------------------------------------------*/

int knot_zone_nsec3_apply_postorder(knot_zone_t *zone,
                              void (*function)(knot_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	return knot_zone_contents_nsec3_apply_postorder(zone->contents,
	                                                  function, data);
}

/*----------------------------------------------------------------------------*/

int knot_zone_nsec3_apply_inorder(knot_zone_t *zone,
                              void (*function)(knot_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	return knot_zone_contents_nsec3_apply_inorder(zone->contents,
	                                                function, data);
}

/*----------------------------------------------------------------------------*/

int knot_zone_nsec3_apply_inorder_reverse(knot_zone_t *zone,
                              void (*function)(knot_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return KNOT_EBADARG;
	}

	return knot_zone_contents_nsec3_apply_inorder_reverse(zone->contents,
	                                                        function, data);
}

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
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
