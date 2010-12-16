/*
 * File     zone-load.c
 * Date     15.12.2010 09:36
 * Author:  Jan Kadlec jan.kadlec@nic.cz
 * Project: CuteDNS
 * Description:   
 */

#include <assert.h>

#include "zone-load.h"
#include "dnslib/dnslib.h"
#include "common.h"
#include "debug.h"
#include "stdio.h"
#include <malloc.h>

static dnslib_dname_t *tmp_dname; 

dnslib_rdata_t *dnslib_load_rdata(uint16_t type, FILE *f)
{
	dnslib_rdata_t *rdata;

	rdata = dnslib_rdata_new();

	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
	assert(desc != NULL);

	dnslib_rdata_item_t *items =
		malloc(sizeof(dnslib_rdata_item_t) * desc->length);

	uint8_t raw_data_length;

	printf("Reading %d items\n", desc->length);

	printf("current type: %d\n", type);

	for (int i = 0; i < desc->length; i++) {
		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME )	{
			items[i].dname = malloc(sizeof(dnslib_dname_t));
			fread(items[i].dname, sizeof(void *), 1, f);
			//TODO find reference to actual rdata
			items[i].dname = tmp_dname;
		} else {
			fread(&raw_data_length, sizeof(raw_data_length), 1, f);
			printf("read len: %d\n", raw_data_length);
			items[i].raw_data =
				malloc(sizeof(uint8_t) * raw_data_length + 1);
			*(items[i].raw_data) = raw_data_length;
			fread(items[i].raw_data + 1, sizeof(uint8_t),
			      raw_data_length, f);
		}
	}

	if (dnslib_rdata_set_items(rdata, items, desc->length) != 0) {
		printf("Error: could not set items\n");
	}

	return rdata;
}

dnslib_rrsig_set_t *dnslib_load_rrsig(FILE *f)
{
	dnslib_rrset_t *rrsig;

	uint16_t rrset_type;
	uint16_t rrset_class;
	uint32_t rrset_ttl;

	uint rdata_count;

	fread(&rrset_type, sizeof(rrset_type), 1, f);
	printf("rrset type: %d\n", rrset_type);
	fread(&rrset_class, sizeof(rrset_class), 1, f);
	printf("rrset class %d\n", rrset_class);
	fread(&rrset_ttl, sizeof(rrset_ttl), 1, f);
	printf("rrset ttl %d\n", rrset_ttl);

	fread(&rdata_count, sizeof(rdata_count), 1, f);

	rrsig = dnslib_rrsig_set_new(NULL, rrset_type, rrset_class, rrset_ttl);

	dnslib_rdata_t *tmp_rdata;

	printf("loading %d rdata entries\n", rdata_count);

	for (int i = 0; i < rdata_count; i++) {
		tmp_rdata = dnslib_load_rdata(DNSLIB_RRTYPE_RRSIG, f);
		dnslib_rrsig_set_add_rdata(rrsig, tmp_rdata);
	}

	return rrsig;
}

dnslib_rrset_t *dnslib_load_rrset(FILE *f)
{
	dnslib_rrset_t *rrset;

	uint16_t rrset_type;
	uint16_t rrset_class;
	uint32_t rrset_ttl;

	uint rdata_count;
	uint rrsig_count;

	fread(&rrset_type, sizeof(rrset_type), 1, f);
	printf("rrset type: %d\n", rrset_type);
	fread(&rrset_class, sizeof(rrset_class), 1, f);
	printf("rrset class %d\n", rrset_class);
	fread(&rrset_ttl, sizeof(rrset_ttl), 1, f);
	printf("rrset ttl %d\n", rrset_ttl);

	fread(&rdata_count, sizeof(rdata_count), 1, f);
	fread(&rrsig_count, sizeof(rrsig_count), 1, f);

	rrset = dnslib_rrset_new(NULL, rrset_type, rrset_class, rrset_ttl);

	dnslib_rdata_t *tmp_rdata;

	printf("loading %d rdata entries\n", rdata_count);

	for (int i = 0; i < rdata_count; i++) {
		tmp_rdata = dnslib_load_rdata(rrset->type, f);
		dnslib_rrset_add_rdata(rrset, tmp_rdata);
	}

	dnslib_rrsig_set_t *tmp_rrsig = NULL;

	if (rrsig_count) {
		tmp_rrsig = dnslib_load_rrsig(f);
	}

	rrset->rrsigs = tmp_rrsig;

	return rrset;
}

dnslib_node_t *dnslib_load_node(FILE *f)
{
	dnslib_node_t *node;
	/* first, owner */
	dnslib_dname_t *owner;

	uint dname_size;
	uint8_t dname_wire[256]; //XXX in respect to remark below, should be dynamic
	uint rrset_count;
	void *dname_id; //ID, technically it's an integer
	
	fread(&dname_size, sizeof(dname_size), 1, f);
	fread(&dname_wire, sizeof(uint8_t), dname_size, f);
	fread(&dname_id, sizeof(dname_id), 1, f);
	fread(&rrset_count, sizeof(rrset_count), 1, f);

	printf("dname_id %p\n", dname_id);
	
	//XXX I already have all thats in the structure, no need to do this
	if ((owner = dnslib_dname_new_from_wire(dname_wire,
		                                dname_size, NULL)) == NULL) {
		return NULL;
	}

	printf("created owner: %s\n", dnslib_dname_to_str(owner));

	if ((node = dnslib_node_new(owner, NULL)) == NULL) {
		printf("Error: could not create node\n");
		return NULL;
	}

	dnslib_rrset_t *tmp_rrset;

	printf("loading %u rrsets\n", rrset_count);

	for (int i = 0; i < rrset_count; i++) {
		if ((tmp_rrset = dnslib_load_rrset(f)) == NULL) {
			dnslib_node_free(&node);
			printf("Error: rrset load\n");
			//TODO what else to free?
			return NULL;
		}
		tmp_rrset->owner = node->owner;
		if (tmp_rrset->rrsigs != NULL) {
			tmp_rrset->rrsigs->owner = node->owner;
		}
		if (dnslib_node_add_rrset(node, tmp_rrset) != 0) {
			printf("Error: could not add rrset\n");
			return NULL;
		}
	}
	assert(node != NULL);
	return node;
}

dnslib_zone_t *dnslib_load_zone(const char *filename)
{
tmp_dname = dnslib_dname_new_from_str("dummy.dname.", 14, NULL);
	FILE *f = fopen(filename, "rb");

	dnslib_node_t *tmp_node;

	uint node_count;

	fread(&node_count, sizeof(node_count), 1, f);

	printf("loading %u nodes\n", node_count);

	for (int i = 0; i < node_count; i++) {
		tmp_node = dnslib_load_node(f);
		if (tmp_node != NULL) {
			dnslib_node_dump(tmp_node);
		} else {
			printf("Node error!\n");
		}
	}

	fclose(f);
}

/* end of file zone-load.c */
