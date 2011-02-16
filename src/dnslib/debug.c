#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

#include "debug.h"
#include "dnslib/dnslib.h"

void dnslib_rdata_dump(dnslib_rdata_t *rdata, uint32_t type, char loaded_zone)
{
#if defined(DNSLIB_ZONE_DEBUG) || defined(DNSLIB_RDATA_DEBUG)
	printf("      ------- RDATA -------\n");
	if (rdata == NULL) {
		printf("      There are no rdata in this RRset!\n");
		printf("      ------- RDATA -------\n");
		return;
	}
	dnslib_rrtype_descriptor_t *desc = dnslib_rrtype_descriptor_by_type(type);
	assert(desc != NULL);
	char *name;

	for (int i = 0; i < rdata->count; i++) {
		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		    desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
		    desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME ) {
			assert(rdata->items[i].dname != NULL);
			name = dnslib_dname_to_str(rdata->items[i].dname);
			printf("      DNAME: %d: %s\n",
			       i, name);
			free(name);
			if (loaded_zone) {
				if (rdata->items[i].dname->node) {
					name =
					dnslib_dname_to_str(rdata->items[i].dname->node->owner);
					printf("      Has node owner: %s\n", name);
					free(name);
				} else {
					printf("      No node set\n");
				}
			}
			printf("      labels: ");
			hex_print((char *)rdata->items[i].dname->labels,
			          rdata->items[i].dname->label_count);

		} else {
			assert(rdata->items[i].raw_data != NULL);
			printf("      %d: raw_data: length: %d\n", i,
			       *(rdata->items[i].raw_data));
			printf("      ");
			hex_print(((char *)(rdata->items[i].raw_data + 1)),
				  rdata->items[i].raw_data[0]);
		}
	}
	printf("      ------- RDATA -------\n");
#endif
}

void dnslib_rrset_dump(dnslib_rrset_t *rrset, char loaded_zone)
{
#if defined(DNSLIB_ZONE_DEBUG) || defined(DNSLIB_RRSET_DEBUG)
	printf("  ------- RRSET -------\n");
	printf("  %p\n", rrset);
	char *name = dnslib_dname_to_str(rrset->owner);
	printf("  owner: %s\n", name);
	free(name);
	printf("  type: %s\n", dnslib_rrtype_to_string(rrset->type));
	printf("  class: %d\n", rrset->rclass);
	printf("  ttl: %d\n", rrset->ttl);

	if (rrset->rrsigs != NULL) {
		printf("  RRSIGs:\n");
		dnslib_rrset_dump(rrset->rrsigs, loaded_zone);
	}

	if (rrset->rdata == NULL) {
		printf("  NO RDATA!\n");
		printf("  ------- RRSET -------\n");
		return;
	}

	dnslib_rdata_t *tmp = rrset->rdata;

	while (tmp->next != rrset->rdata) {
		dnslib_rdata_dump(tmp, rrset->type, loaded_zone);
		tmp = tmp->next;
	}

	dnslib_rdata_dump(tmp, rrset->type, loaded_zone);

	printf("  ------- RRSET -------\n");
#endif
}

void dnslib_node_dump(dnslib_node_t *node, void *data)
{
#if defined(DNSLIB_ZONE_DEBUG) || defined(DNSLIB_NODE_DEBUG)
	char loaded_zone = *((char*) data);
	printf("------- NODE --------\n");
	printf("owner: %s\n", dnslib_dname_to_str(node->owner));
	printf("labels: ");
	hex_print((char *)node->owner->labels, node->owner->label_count);
	printf("node/id: %p\n", node->owner->node);

	if (dnslib_node_is_deleg_point(node)) {
		printf("delegation point\n");
	}

	if (dnslib_node_is_non_auth(node)) {
		printf("non-authoritative node\n");
	}

	char *name;

	if (node->parent != NULL) {
		name = dnslib_dname_to_str(node->parent->owner);
		printf("parent: %s\n", name);
		free(name);
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
		name = dnslib_dname_to_str(node->wildcard_child->owner);
		printf("%s\n", name);
		free(name);
	} else {
		printf("none\n");
	}

	dnslib_rrset_t *tmp = (dnslib_rrset_t *)skip_node->value;

	dnslib_rrset_dump(tmp, loaded_zone);

	while ((skip_node = skip_next(skip_node)) != NULL) {
		tmp = (dnslib_rrset_t *)skip_node->value;
	//	assert(tmp->owner->node == node);
		dnslib_rrset_dump(tmp, loaded_zone);
	}
	//assert(node->owner->node == node);
	printf("------- NODE --------\n");
#endif
}

void dnslib_zone_dump(dnslib_zone_t *zone, char loaded_zone)
{
#if defined(DNSLIB_ZONE_DEBUG)
	printf("------- ZONE --------\n");

	dnslib_zone_tree_apply_inorder(zone, dnslib_node_dump, (void *)&loaded_zone);

	printf("------- ZONE --------\n");
	
	printf("------- NSEC 3 tree -\n");

	dnslib_zone_nsec3_apply_inorder(zone, dnslib_node_dump, (void *)&loaded_zone);

	printf("------- NSEC 3 tree -\n");
#endif
}
