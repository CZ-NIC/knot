#include <stdio.h>
#include <stdint.h>
#include <assert.h>

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
	assert(desc != NULL);
	for (int i = 0; i < desc->length; i++) {
		if (&(rdata->items[i]) == NULL) { //XXX isn't this itself enough to crash?
			printf("Item n. %d is not set!\n", i);
			continue;
		}
		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME )	{
			assert(rdata->items[i].dname != NULL);
			printf("DNAME: %d: %s\n", 
			       i, dnslib_dname_to_str(rdata->items[i].dname));

		} else {
			assert(rdata->items[i].raw_data != NULL);
			printf("%d: raw_data: length: %d\n", i,
			       *(rdata->items[i].raw_data));
		}
	}
	printf("------- RDATA -------\n");
}

void dnslib_rrsig_dump(dnslib_rrsig_set_t *rrsig)
{
	printf("------- RRSIG -------\n");
	if (rrsig == NULL) {
		printf("RRSIG is not set\n");
		printf("------- RRSIG -------\n");
		return;
	}
	printf("type: %s\n", dnslib_rrtype_to_string(rrsig->type));
	printf("class: %d\n", rrsig->rclass);
	printf("ttl: %d\n", rrsig->ttl);

	dnslib_rdata_t *tmp = rrsig->rdata;

	if (tmp == NULL) {
		return;
	}

	while (tmp->next != rrsig->rdata) {
		dnslib_rdata_dump(tmp, DNSLIB_RRTYPE_RRSIG);
		tmp = tmp->next;
	}

	dnslib_rdata_dump(tmp, DNSLIB_RRTYPE_RRSIG); 

	printf("------- RRSIG -------\n");
}

void dnslib_rrset_dump(dnslib_rrset_t *rrset)
{
	printf("------- RRSET -------\n");
	printf("%p\n", rrset);
	printf("type: %s\n", dnslib_rrtype_to_string(rrset->type));
	printf("class: %d\n", rrset->rclass);
	printf("ttl: %d\n", rrset->ttl);

	dnslib_rrsig_dump(rrset->rrsigs);

	if (rrset->rdata == NULL) {
		printf("NO RDATA!\n");
		printf("------- RRSET -------\n");
		return;
	}

	dnslib_rdata_t *tmp = rrset->rdata;

	while (tmp->next != rrset->rdata) {
		dnslib_rdata_dump(tmp, rrset->type);
		tmp = tmp->next;
	}

	dnslib_rdata_dump(tmp, rrset->type);

	printf("------- RRSET -------\n");
}

void dnslib_node_dump(dnslib_node_t *node)
{
	printf("------- NODE --------\n");
	printf("owner: %s\n", dnslib_dname_to_str(node->owner));
	printf("node/id: %p\n", node->owner->node);

	if (node->parent != NULL) {
		printf("parent: %s\n", dnslib_dname_to_str(node->parent->owner));
	} else {
		printf("no parent\n");
	}

	const skip_node_t *skip_node =
		skip_first(node->rrsets);

	if (skip_node == NULL) {
		printf("Node is empty!\n");
		printf("------- NODE --------\n");
		return;
	}

	printf("Wildcard child: ");

	if (node->wildcard_child != NULL) {
		printf("%s\n", dnslib_dname_to_str(node->wildcard_child->owner));
	} else {
		printf("none\n");
	}

	dnslib_rrset_t *tmp = (dnslib_rrset_t *)skip_node->value;

	dnslib_rrset_dump(tmp);

	while ((skip_node = skip_next(skip_node)) != NULL) {
		tmp = (dnslib_rrset_t *)skip_node->value;
	//	assert(tmp->owner->node == node);
		dnslib_rrset_dump(tmp);
	}
	//assert(node->owner->node == node);
	printf("------- NODE --------\n");
}

void dnslib_zone_dump(dnslib_zone_t *zone)
{
	printf("------- ZONE --------\n");

	TREE_FORWARD_APPLY(zone->tree, dnslib_node, avl, dnslib_node_dump, NULL);

	printf("------- ZONE --------\n");
	
	printf("------- NSEC 3 tree -\n");

	TREE_FORWARD_APPLY(zone->nsec3_nodes, dnslib_node, avl, dnslib_node_dump, NULL);

	printf("------- NSEC 3 tree -\n");
}
