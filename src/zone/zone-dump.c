#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include "zone-dump.h"
#include "dnslib.h"

/* TODO Think of a better way than global variable */
static uint node_count = 0;

static uint8_t zero = 0;
static uint8_t one = 1;

static void dnslib_rdata_dump_binary(dnslib_rdata_t *rdata,
                                     uint32_t type, FILE *f)
{
	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
	assert(desc != NULL);
	for (int i = 0; i < desc->length; i++) {
		if (&(rdata->items[i]) == NULL) {
			//XXX isn't this itself enough to crash?
			debug_zp("Item n. %d is not set!\n", i);
			continue;
		}
		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME )	{
			assert(rdata->items[i].dname != NULL);
			if (rdata->items[i].dname->node) { //IN THE ZONE DNAME
				fwrite(&one, sizeof(one), 1, f);
				fwrite(&(rdata->items[i].dname->node),
				       sizeof(void *), 1, f);
			} else {
				debug_zp("not in zone: %s\n",
				       dnslib_dname_to_str((rdata->items[i].dname)));
				fwrite(&zero, sizeof(zero), 1, f);
				fwrite(&(rdata->items[i].dname->size),
				       sizeof(uint), 1, f);
				fwrite(rdata->items[i].dname->name,
				       sizeof(uint8_t),
				       rdata->items[i].dname->size, f);
			}

		} else {
			assert(rdata->items[i].raw_data != NULL);
			fwrite(rdata->items[i].raw_data, sizeof(uint8_t),
			       rdata->items[i].raw_data[0] + 1, f);\

			debug_zp("Written %d long raw data\n",
			         rdata->items[i].raw_data[0]);
		}
	}
}

static void dnslib_rrsig_set_dump_binary(dnslib_rrsig_set_t *rrsig, FILE *f)
{
	fwrite(&rrsig->type, sizeof(rrsig->type), 1, f);
	fwrite(&rrsig->rclass, sizeof(rrsig->rclass), 1, f);
	fwrite(&rrsig->ttl, sizeof(rrsig->ttl), 1, f);

	uint8_t rdata_count = 0;

	fpos_t rrdata_count_pos;

	fgetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);

	assert(rrsig->rdata);

	dnslib_rdata_t *tmp_rdata = rrsig->rdata;

	while (tmp_rdata->next != rrsig->rdata) {
		dnslib_rdata_dump_binary(tmp_rdata, DNSLIB_RRTYPE_RRSIG, f);
		tmp_rdata = tmp_rdata->next;
		rdata_count++;
	}
	dnslib_rdata_dump_binary(tmp_rdata, DNSLIB_RRTYPE_RRSIG, f);
	rdata_count++;

	fpos_t tmp_pos;

	fgetpos(f, &tmp_pos);

	fsetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);

	fsetpos(f, &tmp_pos);
}

static void dnslib_rrset_dump_binary(dnslib_rrset_t *rrset, FILE *f)
{
	fwrite(&rrset->type, sizeof(rrset->type), 1, f);
	fwrite(&rrset->rclass, sizeof(rrset->rclass), 1, f);
	fwrite(&rrset->ttl, sizeof(rrset->ttl), 1, f);

	uint8_t rdata_count = 0;
	uint8_t rrsig_count = 0;

	fpos_t rrdata_count_pos;

	fgetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);
	fwrite(&rrsig_count, sizeof(rrsig_count), 1, f);

	dnslib_rdata_t *tmp_rdata = rrset->rdata;

	while (tmp_rdata->next != rrset->rdata) {
		dnslib_rdata_dump_binary(tmp_rdata, rrset->type, f);
		tmp_rdata = tmp_rdata->next;
		rdata_count++;
	}
	dnslib_rdata_dump_binary(tmp_rdata, rrset->type, f);
	rdata_count++;

	if (rrset->rrsigs != NULL) {
		dnslib_rrsig_set_dump_binary(rrset->rrsigs, f);
		rrsig_count = 1;
	}

	fpos_t tmp_pos;

	fgetpos(f, &tmp_pos);

	fsetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);
	fwrite(&rrsig_count, sizeof(rrsig_count), 1, f);	

	fsetpos(f, &tmp_pos);
}

static void dnslib_node_dump_binary(dnslib_node_t *node, FILE *f)
{
	node_count++;
	/* first write dname */
	assert(node->owner != NULL);
	fwrite(&((node->owner->size)), sizeof(uint8_t), 1, f);

	debug_zp("Size written: %u\n", node->owner->size);

	fwrite(node->owner->name, sizeof(uint8_t),
	       node->owner->size, f);

	fwrite(&(node->owner->node), sizeof(void *), 1, f);

	debug_zp("Writing id: %u\n", node->owner->node);


	if (node->parent != NULL) {
		fwrite(&(node->parent->owner->node), sizeof(void *), 1, f);
	} else {
		fwrite(&(node->parent), sizeof(void *), 1, f);
	}

	/* Now we need (or do we?) count of rrsets to be read 
	 * but that number is yet unknown */

	fpos_t rrset_count_pos;

	fgetpos(f, &rrset_count_pos);

	debug_zp("Position rrset_count: %ld\n", ftell(f));

	uint8_t rrset_count = 0;

	fwrite(&rrset_count, sizeof(rrset_count), 1, f);

	const skip_node_t *skip_node = skip_first(node->rrsets);

	if (skip_node == NULL) {
		/* we can return, count is set to 0 */
		return;
	}
	
	dnslib_rrset_t *tmp;

	do {
		tmp = (dnslib_rrset_t *)skip_node->value;
		rrset_count++;
		dnslib_rrset_dump_binary(tmp, f);
	} while ((skip_node = skip_next(skip_node)) != NULL);

	fpos_t tmp_pos;

	fgetpos(f, &tmp_pos);

	debug_zp("Position after all rrsets: %ld\n", ftell(f));

	fsetpos(f, &rrset_count_pos);

	debug_zp("Writing here: %ld\n", ftell(f));	

	fwrite(&rrset_count, sizeof(rrset_count), 1, f);

	fsetpos(f, &tmp_pos);

	debug_zp("Function ends with: %ld\n\n", ftell(f));	

}

static void dnslib_node_dump_binary_from_tree(dnslib_node_t *node, void *data)
{
	dnslib_node_dump_binary(node, (FILE *)data);
}

int dnslib_zone_dump_binary(dnslib_zone_t *zone, const char *filename)
{
	FILE *f;

	f = fopen(filename, "wb");

	if (f == NULL) {
		return -1;
	}

	fwrite(&node_count, sizeof(node_count), 1, f);
	fwrite(&node_count, sizeof(node_count), 1, f);

	fwrite(&(zone->apex->owner->size),
	       sizeof(uint8_t), 1, f);

	fwrite(zone->apex->owner->name, sizeof(uint8_t),
	       zone->apex->owner->size, f);
	
	/* TODO is there a way how to stop the traversal upon error? */
	dnslib_zone_tree_apply_inorder_reverse(
		zone, dnslib_node_dump_binary_from_tree, (void *)f);
//	TREE_REVERSE_APPLY(zone->tree, dnslib_node, avl,
//	                   dnslib_node_dump_binary, f);

	uint tmp_count = node_count;

	node_count = 0;

	dnslib_zone_nsec3_apply_inorder_reverse(
		zone, dnslib_node_dump_binary_from_tree, (void *)f);
//	TREE_REVERSE_APPLY(zone->nsec3_nodes, dnslib_node, avl,
//	                   dnslib_node_dump_binary, f);

	rewind(f);
	
	fwrite(&tmp_count, sizeof(tmp_count), 1, f);
	fwrite(&node_count, sizeof(node_count), 1, f);

	printf("written %d normal nodes\n", tmp_count);

	printf("written %d nsec3 nodes\n", node_count);

	fclose(f);

	return 0;
}

