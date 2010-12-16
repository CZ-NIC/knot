/*
 * File     zone-dump.c
 * Date     14.12.2010 19:52
 * Author:  Jan Kadlec jan.kadlec@nic.cz
 * Project: CuteDNS
 * Description:   
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include "zone-dump.h"
#include "dnslib/dnslib.h"

/* TODO Think of a better way than global variable */
static uint node_count = 0;

void dnslib_rdata_dump_binary(dnslib_rdata_t *rdata, uint32_t type, FILE *f)
{
	printf("dumping rdata\n");
	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
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
			fwrite(&(rdata->items[i].dname), sizeof(void *), 1, f);

		} else {
			assert(rdata->items[i].raw_data != NULL);
			fwrite(rdata->items[i].raw_data, sizeof(uint8_t),
			       rdata->items[i].raw_data[0] + 1, f);\

			printf("Written %d long raw data\n", rdata->items[i].raw_data[0]);
		}
	}
}

void dnslib_rrsig_set_dump_binary(dnslib_rrsig_set_t *rrsig, FILE *f)
{
	fwrite(&rrsig->type, sizeof(rrsig->type), 1, f);
	fwrite(&rrsig->rclass, sizeof(rrsig->rclass), 1, f);
	fwrite(&rrsig->ttl, sizeof(rrsig->ttl), 1, f);

	uint rdata_count = 0;

	fpos_t rrdata_count_pos;

	fgetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);

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

void dnslib_rrset_dump_binary(dnslib_rrset_t *rrset, FILE *f)
{
	fwrite(&rrset->type, sizeof(rrset->type), 1, f);
	fwrite(&rrset->rclass, sizeof(rrset->rclass), 1, f);
	fwrite(&rrset->ttl, sizeof(rrset->ttl), 1, f);

	uint rdata_count = 0;
	uint rrsig_count = 0;

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

void dnslib_node_dump_binary(dnslib_node_t *node, FILE *f)
{
	/* first write dname */
	assert(node->owner != NULL);
	fwrite(&node->owner->size, sizeof(node->owner->size), 1, f);

	fwrite(node->owner->name, sizeof(uint8_t),
	       node->owner->size, f);

	fwrite(&(node->owner), sizeof(void *),
	       1, f);

	/* Now we need (or do we?) count of rrsets to be read 
	 * but that number is yet unknown */

	fpos_t rrset_count_pos;

	fgetpos(f, &rrset_count_pos);

	printf("Position rrset_count: %ld\n", ftell(f));

	uint rrset_count = 0;

	fwrite(&rrset_count, sizeof(rrset_count), 1, f);

	const skip_node_t *skip_node = skip_first(node->rrsets);

	if (skip_node == NULL) {
		/* we can return, count is set to 0 */
		return;
	}
	
	dnslib_rrset_t *tmp;

	do {
		tmp = (dnslib_rrset_t *)skip_node->value;
		assert(tmp->owner->node == node);
		rrset_count++;
		dnslib_rrset_dump_binary(tmp, f);
	} while ((skip_node = skip_next(skip_node)) != NULL);

	const fpos_t tmp_pos;

	fgetpos(f, &tmp_pos);

	printf("Position after all rrsets: %ld\n", ftell(f));

	fsetpos(f, &rrset_count_pos);

	printf("Writing here: %ld\n", ftell(f));	

	fwrite(&rrset_count, sizeof(rrset_count), 1, f);

	fsetpos(f, &tmp_pos);

	printf("Number of rrsets: %u\n", rrset_count);

	printf("Function ends with: %ld\n\n", ftell(f));	

	node_count++;
}

int dnslib_zone_dump_binary(dnslib_zone_t *zone, const char *filename)
{
	FILE *f;

	f = fopen(filename, "wb");

	if (f == NULL) {
		return -1;
	}

	fwrite(&node_count, sizeof(node_count), 1, f);
	
	/* TODO is there a way how to stop the traversal upon error? */
	TREE_FORWARD_APPLY(zone->tree, dnslib_node, avl,
	                   dnslib_node_dump_binary, f);

	rewind(f);

	fwrite(&node_count, sizeof(node_count), 1, f);

	fclose(f);

	return 0;
}

/*
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
			printf("%d: %s\n", 
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
}*/
/* end of file zone-dump.c */
