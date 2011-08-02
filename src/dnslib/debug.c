#include <config.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

#include "dnslib/utils.h"
#include "dnslib/debug.h"
#include "dnslib/dnslib.h"
#include "common/print.h"

void knot_rdata_dump(knot_rdata_t *rdata, uint32_t type, char loaded_zone)
{
#if defined(DNSLIB_ZONE_DEBUG) || defined(DNSLIB_RDATA_DEBUG)
	printf("      ------- RDATA -------\n");
	if (rdata == NULL) {
		printf("      There are no rdata in this RRset!\n");
		printf("      ------- RDATA -------\n");
		return;
	}
	knot_rrtype_descriptor_t *desc = knot_rrtype_descriptor_by_type(type);
	assert(desc != NULL);
	char *name;

	for (int i = 0; i < rdata->count; i++) {
		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		    desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
		    desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME ) {
			assert(rdata->items[i].dname != NULL);
			name = knot_dname_to_str(rdata->items[i].dname);
			printf("      DNAME: %d: %s\n",
			       i, name);
			free(name);
			if (loaded_zone) {
				if (rdata->items[i].dname->node) {
					name =
					knot_dname_to_str(rdata->items[i].dname->node->owner);
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
			hex_print(((char *)(
				rdata->items[i].raw_data + 1)),
				rdata->items[i].raw_data[0]);
		}
	}
	printf("      ------- RDATA -------\n");
#endif
}

void knot_rrset_dump(knot_rrset_t *rrset, char loaded_zone)
{
#if defined(DNSLIB_ZONE_DEBUG) || defined(DNSLIB_RRSET_DEBUG)
	printf("  ------- RRSET -------\n");
	printf("  %p\n", rrset);
        char *name = knot_dname_to_str(rrset->owner);
        printf("  owner: %s\n", name);
        free(name);
	printf("  type: %s\n", knot_rrtype_to_string(rrset->type));
	printf("  class: %d\n", rrset->rclass);
	printf("  ttl: %d\n", rrset->ttl);

        printf("  RRSIGs:\n");
        if (rrset->rrsigs != NULL) {
                knot_rrset_dump(rrset->rrsigs, loaded_zone);
        } else {
                printf("  none\n");
        }

	if (rrset->rdata == NULL) {
		printf("  NO RDATA!\n");
		printf("  ------- RRSET -------\n");
		return;
	}

	knot_rdata_t *tmp = rrset->rdata;

	while (tmp->next != rrset->rdata) {
		knot_rdata_dump(tmp, rrset->type, loaded_zone);
		tmp = tmp->next;
	}

	knot_rdata_dump(tmp, rrset->type, loaded_zone);

	printf("  ------- RRSET -------\n");
#endif
}

void knot_node_dump(knot_node_t *node, void *loaded_zone)
{
#if defined(DNSLIB_ZONE_DEBUG) || defined(DNSLIB_NODE_DEBUG)
	//char loaded_zone = *((char*) data);
	char *name;

	printf("------- NODE --------\n");
	name = knot_dname_to_str(node->owner);
	printf("owner: %s\n", name);
	free(name);
	printf("labels: ");
	hex_print((char *)node->owner->labels, node->owner->label_count);
	printf("node/id: %p\n", node->owner->node);
	if (loaded_zone && node->prev != NULL) {
		name = knot_dname_to_str(node->prev->owner);
		printf("previous node: %s\n", name);
		free(name);
	}

	if (knot_node_is_deleg_point(node)) {
		printf("delegation point\n");
	}

	if (knot_node_is_non_auth(node)) {
		printf("non-authoritative node\n");
	}

	if (node->parent != NULL) {
		name = knot_dname_to_str(node->parent->owner);
		printf("parent: %s\n", name);
		free(name);
	} else {
		printf("no parent\n");
	}

	if (node->prev != NULL) {
		name = knot_dname_to_str(node->prev->owner);
		printf("previous node: %s\n", name);
		free(name);
	} else {
		printf("previous node: none\n");
	}

	knot_rrset_t **rrsets = knot_node_get_rrsets(node);

	printf("Wildcard child: ");

	if (node->wildcard_child != NULL) {
		name = knot_dname_to_str(node->wildcard_child->owner);
		printf("%s\n", name);
		free(name);
	} else {
		printf("none\n");
	}

	printf("NSEC3 node: ");

	if (node->nsec3_node != NULL) {
		name = knot_dname_to_str(node->nsec3_node->owner);
		printf("%s\n", name);
		free(name);
	} else {
		printf("none\n");
	}

	printf("RRSet count: %d\n", node->rrset_count);

	for (int i = 0; i < node->rrset_count; i++) {
		knot_rrset_dump(rrsets[i], (int) loaded_zone);
	}
	//assert(node->owner->node == node);
	printf("------- NODE --------\n");
#endif
}

void knot_zone_contents_dump(knot_zone_contents_t *zone, char loaded_zone)
{
#if defined(DNSLIB_ZONE_DEBUG)
	printf("------- ZONE --------\n");

	knot_zone_contents_tree_apply_inorder(zone, knot_node_dump, (void *)&loaded_zone);

	printf("------- ZONE --------\n");
	
	printf("------- NSEC 3 tree -\n");

	knot_zone_contents_nsec3_apply_inorder(zone, knot_node_dump, (void *)&loaded_zone);

	printf("------- NSEC 3 tree -\n");
#endif
}
