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

dnslib_zone_t *dnslib_zone_new(dnslib_node_t *apex, uint node_count,
                               int use_domain_table)
{
	debug_dnslib_zone("Creating new zone!\n");
	if (apex == NULL) {
		return NULL;
	}

	dnslib_zone_t *zone = (dnslib_zone_t *)calloc(1, sizeof(dnslib_zone_t));
	if (zone == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	// save the zone name
	debug_dnslib_zone("Copying zone name.\n");
	zone->name = dnslib_dname_deep_copy(dnslib_node_owner(apex));
	if (zone->name == NULL) {
		ERR_ALLOC_FAILED;
		free(zone);
		return NULL;
	}

	debug_dnslib_zone("Creating zone contents.\n");
	zone->contents = dnslib_zone_contents_new(apex, node_count,
	                                          use_domain_table, zone);
	if (zone->contents == NULL) {
		dnslib_dname_release(zone->name);
		free(zone);
		return NULL;
	}

	debug_dnslib_zone("Initializing zone data.\n");
	/* Initialize data. */
	zone->data = 0;
	zone->dtor = 0;

	return zone;
}

/*----------------------------------------------------------------------------*/

dnslib_zone_contents_t *dnslib_zone_get_contents(
	const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return rcu_dereference(zone->contents);
}

/*----------------------------------------------------------------------------*/

const dnslib_zone_contents_t *dnslib_zone_contents(
	const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return rcu_dereference(zone->contents);
}

/*----------------------------------------------------------------------------*/

time_t dnslib_zone_version(const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return zone->version;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_set_version(dnslib_zone_t *zone, time_t version)
{
	if (zone == NULL) {
		return;
	}

	zone->version = version;
}

/*----------------------------------------------------------------------------*/

const void *dnslib_zone_data(const dnslib_zone_t *zone)
{
	return zone->data;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_set_data(dnslib_zone_t *zone, void *data)
{
	zone->data = data;
}

/*----------------------------------------------------------------------------*/
/* Zone contents functions. TODO: remove                                      */
/*----------------------------------------------------------------------------*/

int dnslib_zone_add_node(dnslib_zone_t *zone, dnslib_node_t *node,
                         int create_parents, int use_domain_table)
{
	if (zone == NULL || node == NULL) {
		return DNSLIB_EBADARG;
	}

	dnslib_node_set_zone(node, zone);

	return dnslib_zone_contents_add_node(zone->contents, node,
	                                     create_parents, 0,
	                                     use_domain_table);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_add_nsec3_node(dnslib_zone_t *zone, dnslib_node_t *node,
                               int create_parents, int use_domain_table)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_add_nsec3_node(zone->contents, node,
	                                           create_parents, 0,
	                                           use_domain_table);
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_zone_get_node(const dnslib_zone_t *zone,
                                    const dnslib_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_get_node(zone->contents, name);
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_zone_get_nsec3_node(const dnslib_zone_t *zone,
                                          const dnslib_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_get_nsec3_node(zone->contents, name);
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_find_node(const dnslib_zone_t *zone,
                                           const dnslib_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_find_node(zone->contents, name);
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_find_nsec3_node(const dnslib_zone_t *zone,
                                                 const dnslib_dname_t *name)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_find_nsec3_node(zone->contents, name);
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_apex(const dnslib_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	return dnslib_zone_contents_apex(zone->contents);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_apply_postorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_tree_apply_postorder(zone->contents,
	                                                 function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_apply_inorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_tree_apply_inorder(zone->contents,
	                                               function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_apply_inorder_reverse(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_tree_apply_inorder_reverse(zone->contents,
	                                                       function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_nsec3_apply_postorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_nsec3_apply_postorder(zone->contents,
	                                                  function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_nsec3_apply_inorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_nsec3_apply_inorder(zone->contents,
	                                                function, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_nsec3_apply_inorder_reverse(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data)
{
	if (zone == NULL) {
		return DNSLIB_EBADARG;
	}

	return dnslib_zone_contents_nsec3_apply_inorder_reverse(zone->contents,
	                                                        function, data);
}

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

dnslib_zone_contents_t *dnslib_zone_switch_contents(dnslib_zone_t *zone,
                                           dnslib_zone_contents_t *new_contents)
{
	if (zone == NULL) {
		return NULL;
	}

	dnslib_zone_contents_t *old_contents =
		rcu_xchg_pointer(&zone->contents, new_contents);
	return old_contents;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_free(dnslib_zone_t **zone)
{
	if (zone == NULL || *zone == NULL) {
		return;
	}

	debug_dnslib_zone("zone_free().\n");

	if ((*zone)->contents && (*zone)->contents->generation != 0) {
		// zone is in the middle of an update, report
		debug_dnslib_zone("Destroying zone that is in the middle of an "
		                  "update.\n");
	}

	dnslib_dname_release((*zone)->name);

	/* Call zone data destructor if exists. */
	if ((*zone)->dtor) {
		(*zone)->dtor(*zone);
	}

	dnslib_zone_contents_free(&(*zone)->contents);
	free(*zone);
	*zone = NULL;

	debug_dnslib_zone("Done.\n");
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_deep_free(dnslib_zone_t **zone, int free_rdata_dnames)
{
	if (zone == NULL || *zone == NULL) {
		return;
	}

	if ((*zone)->contents->generation != 0) {
		// zone is in the middle of an update, report
		debug_dnslib_zone("Destroying zone that is in the middle of an "
		                  "update.\n");
	}

DEBUG_DNSLIB_ZONE(
	char *name = dnslib_dname_to_str((*zone)->name);
	debug_dnslib_zone("Destroying zone %p, name: %s.\n", *zone, name);
	free(name);
);

	dnslib_dname_release((*zone)->name);

	/* Call zone data destructor if exists. */
	if ((*zone)->dtor) {
		(*zone)->dtor(*zone);
	}

	dnslib_zone_contents_deep_free(&(*zone)->contents);
	free(*zone);
	*zone = NULL;
}
