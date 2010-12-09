#include <stdlib.h>
#include <assert.h>

#include "zone.h"
#include "common.h"
#include "node.h"
#include "dname.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

int dnslib_zone_check_node(const dnslib_zone_t *zone, const dnslib_node_t *node)
{
	if (zone == NULL || node == NULL) {
		return -1;
	}

	// assert or just check??
	assert(zone->apex != NULL);

	if (!dnslib_dname_is_subdomain(node->owner, zone->apex->owner)) {
		char *node_owner = dnslib_dname_to_str(node->owner);
		char *apex_owner = dnslib_dname_to_str(zone->apex->owner);
		log_error("Trying to insert foreign node to a zone."
			  "Node owner: %s, zone apex: %s\n",
			  node_owner, apex_owner);
		free(node_owner);
		free(apex_owner);
		return -2;
	}
	return 0;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_zone_t *dnslib_zone_new(dnslib_node_t *apex)
{
	if (apex == NULL) {
		return NULL;
	}

	dnslib_zone_t *zone = (dnslib_zone_t *)malloc(sizeof(dnslib_zone_t));
	if (zone == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	zone->apex = apex;
	return zone;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_add_node(dnslib_zone_t *zone, dnslib_node_t *node)
{
	int ret = 0;
	if ((ret = dnslib_zone_check_node(zone, node)) != 0) {
		return ret;
	}

	dnslib_node_t *n = zone->apex;
	while (n->next != NULL) {
		n = n->next;
	}
	n->next = node;
	node->next = NULL;

	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_add_nsec3_node(dnslib_zone_t *zone, dnslib_node_t *node)
{
	int ret = 0;
	if ((ret = dnslib_zone_check_node(zone, node)) != 0) {
		return ret;
	}

	dnslib_node_t *n = zone->nsec3_nodes;
	while (n->next != NULL) {
		n = n->next;
	}
	n->next = node;
	node->next = NULL;

	return 0;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_zone_get_node(dnslib_zone_t *zone,
                                    const dnslib_dname_t *name)
{
	if (zone == NULL || name == NULL) {
		return NULL;
	}

	dnslib_node_t *n = zone->apex;
	while (n != NULL && dnslib_dname_compare(n->owner, name) != 0) {
		n = n->next;
	}
	return n;
}

/*----------------------------------------------------------------------------*/

const dnslib_node_t *dnslib_zone_find_node(dnslib_zone_t *zone,
                                           const dnslib_dname_t *name)
{
	return dnslib_zone_get_node(zone, name);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_free(dnslib_zone_t **zone, int free_nodes)
{
	if (zone == NULL || *zone == NULL) {
		return;
	}

	if (free_nodes && (*zone)->apex != NULL) {
		dnslib_node_t *n = (*zone)->apex;
		(*zone)->apex = NULL;
		dnslib_node_t *next = n->next;
		while (next != NULL) {
			dnslib_node_free(&n);
			n = next;
			next = n->next;
		}
	}

	free(*zone);
	*zone = NULL;
}
