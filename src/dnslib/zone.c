#include <stdlib.h>
#include <assert.h>

#include "zone.h"
#include "common.h"
#include "node.h"
#include "dname.h"

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
	if (zone == NULL || node == NULL) {
		return -1;
	}
	


	//valgrind test

	dnslib_node_t *test = zone->apex->next;


	// assert or just check??
	assert(zone->apex != NULL);

	dnslib_node_t *n = zone->apex;
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
	printf("%s WITH %s\n", dnslib_dname_to_str(n->owner), dnslib_dname_to_str(name));

	printf("RESULT %d\n", dnslib_dname_compare(n->owner, name));
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
