#include <stdio.h>
#include <stdint.h>

#include "debug.h"
#include "dnslib/dnslib.h"

void dnslib_rdata_dump(dnslib_rdata_t *rdata, uint32_t type)
{
	printf("------- RDATA -------\n");
	if (rdata == NULL) {
		printf("There are no rdata in this RRset!\n");
		printf("------- RDATA -------\n");
		return;
	}

	dnslib_rrtype_descriptor_t *desc = dnslib_rrtype_descriptor_by_type(type);
	for (int i = 0; i < desc->length; i++) {
		if (&(rdata->items[i]) == NULL) { //XXX isn't this itself enough to crash?
			printf("Item n. %d is not set!\n", i);
			continue;
		}
		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
		DNSLIB_RDATA_WF_LITERAL_DNAME )	{
			printf("%d: %s\n", 
			       i, dnslib_dname_to_str(rdata->items[i].dname));

		} else {
			printf("%d: %s\n", i, rdata->items[i].raw_data);
		}
	}
	printf("------- RDATA -------\n");
}

void dnslib_rrset_dump(dnslib_rrset_t *rrset)
{
	printf("------- RRSET -------\n");
	//TODO textual repre. from descriptor
	printf("type: %d\n", rrset->type);
	printf("class: %d\n", rrset->rclass);
	printf("ttl: %d\n", rrset->ttl);

	dnslib_rdata_t *tmp = rrset->rdata;

//	while (tmp->next != NULL) {
//		dnslib_rdata_dump(tmp, rrset->type);
//		tmp = tmp->next;
//	}
	printf("------- RRSET -------\n");
}

void dnslib_node_dump(dnslib_node_t *node)
{
	printf("------- NODE --------\n");
//	printf("owner: %s\n", dnslib_dname_to_str(node->owner));

	printf("owner: %s\n", node->owner->name);

	const skip_node_t *skip_node =
		skip_first(node->rrsets);

	if (skip_node == NULL) {
		printf("Node is empty!\n");
		printf("------- NODE --------\n");
		return;
	}

	dnslib_rrset_t *tmp = (dnslib_rrset_t *)skip_node->value;
	dnslib_rrset_dump(tmp);

	while ((skip_node = skip_next(skip_node)) != NULL) {
		tmp = (dnslib_rrset_t *)skip_node->value;
		dnslib_rrset_dump(tmp);
	}
	printf("------- NODE --------\n");
}

void dnslib_zone_dump(dnslib_zone_t *zone)
{
	printf("------- ZONE --------\n");
	dnslib_node_t *tmp = zone->apex;

	while (tmp->next != NULL) {
		dnslib_node_dump(tmp);
		tmp = tmp->next;
	}

	dnslib_node_dump(tmp);
		
	printf("------- ZONE --------\n");
}
