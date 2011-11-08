/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include "common.h"
#include "rrset.h"
#include "util/descriptor.h"
#include "util/error.h"
#include "util/utils.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static void knot_rrset_disconnect_rdata(knot_rrset_t *rrset,
                                    knot_rdata_t *prev, knot_rdata_t *rdata)
{
	if (prev == NULL) {
		// find the previous RDATA in the series, as its pointer must
		// be changed
		prev = rdata->next;
		while (prev->next != rdata) {
			prev = prev->next;
		}
	}

	assert(prev);
	assert(prev->next == rdata);

	prev->next = rdata->next;

	if (rrset->rdata == rdata) {
		if (rdata->next == rdata) {
			rrset->rdata = NULL;
		} else {
			rrset->rdata = rdata->next;
		}
	}
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_rrset_t *knot_rrset_new(knot_dname_t *owner, uint16_t type,
                                 uint16_t rclass, uint32_t ttl)
{
	knot_rrset_t *ret = malloc(sizeof(knot_rrset_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ret->rdata = NULL;

	/* Retain reference to owner. */
	knot_dname_retain(owner);

	ret->owner = owner;
	ret->type = type;
	ret->rclass = rclass;
	ret->ttl = ttl;
	ret->rrsigs = NULL;

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_add_rdata(knot_rrset_t *rrset, knot_rdata_t *rdata)
{
	if (rrset == NULL || rdata == NULL) {
		return KNOT_EBADARG;
	}

	if (rrset->rdata == NULL) {
		rrset->rdata = rdata;
		rrset->rdata->next = rrset->rdata;
	} else {
		knot_rdata_t *tmp;

		tmp = rrset->rdata;

		while (tmp->next != rrset->rdata) {
			tmp = tmp->next;
		}
		rdata->next = tmp->next;
		tmp->next = rdata;
	}
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

knot_rdata_t *knot_rrset_remove_rdata(knot_rrset_t *rrset,
                                          const knot_rdata_t *rdata)
{
	if (rrset == NULL || rdata == NULL) {
		return NULL;
	}

	knot_rdata_t *prev = NULL;
	knot_rdata_t *rr = rrset->rdata;
	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(rrset->type);

	if (desc == NULL) {
		return NULL;
	}

	while (rr != NULL) {
		/*! \todo maybe the dnames should be compared case-insensitive*/
		if (knot_rdata_compare(rr, rdata, desc->wireformat) == 0) {
			knot_rrset_disconnect_rdata(rrset, prev, rr);
			return rr;
		}
		prev = rr;
		rr = knot_rrset_rdata_get_next(rrset, rr);
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_set_rrsigs(knot_rrset_t *rrset, knot_rrset_t *rrsigs)
{
	if (rrset == NULL) {
		return KNOT_EBADARG;
	}

	rrset->rrsigs = rrsigs;
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_add_rrsigs(knot_rrset_t *rrset, knot_rrset_t *rrsigs,
                            knot_rrset_dupl_handling_t dupl)
{
	if (rrset == NULL || rrsigs == NULL
	    || knot_dname_compare(rrset->owner, rrsigs->owner) != 0) {
		return KNOT_EBADARG;
	}

	int rc;
	if (rrset->rrsigs != NULL) {
		if (dupl == KNOT_RRSET_DUPL_MERGE) {
			rc = knot_rrset_merge((void **)&rrset->rrsigs,
			                        (void **)&rrsigs);
			if (rc != KNOT_EOK) {
				return rc;
			} else {
				return 1;
			}
		} else if (dupl == KNOT_RRSET_DUPL_SKIP) {
			return 2;
		} else if (dupl == KNOT_RRSET_DUPL_REPLACE) {
			rrset->rrsigs = rrsigs;
		}
	} else {
		rrset->rrsigs = rrsigs;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_rrset_owner(const knot_rrset_t *rrset)
{
	return rrset->owner;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_rrset_get_owner(const knot_rrset_t *rrset)
{
	return rrset->owner;
}

/*----------------------------------------------------------------------------*/

void knot_rrset_set_owner(knot_rrset_t *rrset, knot_dname_t* owner)
{
	if (rrset) {
		/* Retain new owner and release old owner. */
		knot_dname_retain(owner);
		knot_dname_release(rrset->owner);
		rrset->owner = owner;
	}
}

/*----------------------------------------------------------------------------*/

uint16_t knot_rrset_type(const knot_rrset_t *rrset)
{
	return rrset->type;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_rrset_class(const knot_rrset_t *rrset)
{
	return rrset->rclass;
}

/*----------------------------------------------------------------------------*/

uint32_t knot_rrset_ttl(const knot_rrset_t *rrset)
{
	return rrset->ttl;
}

/*----------------------------------------------------------------------------*/

const knot_rdata_t *knot_rrset_rdata(const knot_rrset_t *rrset)
{
	return rrset->rdata;
}

/*----------------------------------------------------------------------------*/

const knot_rdata_t *knot_rrset_rdata_next(const knot_rrset_t *rrset,
                                              const knot_rdata_t *rdata)
{
	if (rdata == NULL) {
		return rrset->rdata;
	}
	if (rdata->next == rrset->rdata) {
		return NULL;
	} else {
		return rdata->next;
	}
}

/*----------------------------------------------------------------------------*/

knot_rdata_t *knot_rrset_get_rdata(knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	} else {
		return rrset->rdata;
	}
}

/*----------------------------------------------------------------------------*/

knot_rdata_t *knot_rrset_rdata_get_next(knot_rrset_t *rrset,
                                            knot_rdata_t *rdata)
{
	if (rdata->next == rrset->rdata) {
		return NULL;
	} else {
		return rdata->next;
	}
}

/*----------------------------------------------------------------------------*/

int knot_rrset_rdata_rr_count(const knot_rrset_t *rrset)
{
	int count = 0;
	const knot_rdata_t *rdata = rrset->rdata;
	
	while (rdata != NULL) {
		++count;
		rdata = knot_rrset_rdata_next(rrset, rdata);
	}
	
	return count;
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_rrset_rrsigs(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		assert(0);
		return NULL;
	} else {
		return rrset->rrsigs;
	}
}

/*----------------------------------------------------------------------------*/

knot_rrset_t *knot_rrset_get_rrsigs(knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		assert(0);
		return NULL;
	} else {
		return rrset->rrsigs;
	}
}

/*----------------------------------------------------------------------------*/

int knot_rrset_compare_rdata(const knot_rrset_t *r1, const knot_rrset_t *r2)
{
	if (r1 == NULL || r2 == NULL) {
		return KNOT_EBADARG;
	}

	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(r1->type);
	if (desc == NULL) {
		return KNOT_EBADARG;
	}

	// compare RDATA sets (order is not significant)
	const knot_rdata_t *rdata1= knot_rrset_rdata(r1);
	const knot_rdata_t *rdata2;

	// find all RDATA from r1 in r2
	while (rdata1 != NULL) {
		 rdata2 = knot_rrset_rdata(r2);
		 while (rdata2 != NULL && knot_rdata_compare(rdata1, rdata2,
		                                            desc->wireformat)) {
			 rdata2 = knot_rrset_rdata_next(r2, rdata2);
		 }

		 if (rdata2 == NULL) {
			 // RDATA from r1 not found in r2
			 return 0;
		 }

		 // otherwise it was found, continue with next r1 RDATA
		 rdata1 = knot_rrset_rdata_next(r1, rdata1);
	}

	// find all RDATA from r2 in r1 (this can be done in a better way)
	rdata2 = knot_rrset_rdata(r2);
	while (rdata2 != NULL) {
		 rdata1 = knot_rrset_rdata(r1);
		 while (rdata2 != NULL && knot_rdata_compare(rdata1, rdata2,
		                                            desc->wireformat)) {
			 rdata1 = knot_rrset_rdata_next(r1, rdata1);
		 }

		 if (rdata1 == NULL) {
			 // RDATA from r1 not found in r2
			 return 0;
		 }

		 // otherwise it was found, continue with next r1 RDATA
		 rdata2 = knot_rrset_rdata_next(r2, rdata2);
	}

	// all RDATA found
	return 1;
}

/*----------------------------------------------------------------------------*/

static int knot_rrset_rr_to_wire(const knot_rrset_t *rrset, 
                                 const knot_rdata_t *rdata, uint8_t **pos,
                                 size_t max_size)
{
	int size = 0;
	
	assert(rrset != NULL);
	assert(rrset->owner != NULL);
	assert(rdata != NULL);
	assert(pos != NULL);
	assert(*pos != NULL);
	
	fprintf(stderr, "Max size: %zu, owner: %p, owner size: %d\n",
	        max_size, rrset->owner, rrset->owner->size);

	// check if owner fits
	if (size + knot_dname_size(rrset->owner) + 10 > max_size) {
		return KNOT_ESPACE;
	}
	
	memcpy(*pos, knot_dname_name(rrset->owner), 
	       knot_dname_size(rrset->owner));
	*pos += knot_dname_size(rrset->owner);
	size += knot_dname_size(rrset->owner);
	
	fprintf(stderr, "Max size: %zu, size: %d\n", max_size, size);

	fprintf(stderr, "Wire format:\n");

	// put rest of RR 'header'
	knot_wire_write_u16(*pos, rrset->type);
	fprintf(stderr, "  Type: %u\n", rrset->type);
	*pos += 2;

	knot_wire_write_u16(*pos, rrset->rclass);
	fprintf(stderr, "  Class: %u\n", rrset->rclass);
	*pos += 2;

	knot_wire_write_u32(*pos, rrset->ttl);
	fprintf(stderr, "  TTL: %u\n", rrset->ttl);
	*pos += 4;

	// save space for RDLENGTH
	uint8_t *rdlength_pos = *pos;
	*pos += 2;

	size += 10;
//	compr->wire_pos += size;
	
	fprintf(stderr, "Max size: %zu, size: %d\n", max_size, size);

	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(rrset->type);

	uint16_t rdlength = 0;

	for (int i = 0; i < rdata->count; ++i) {
		if (max_size < size + rdlength) {
			return KNOT_ESPACE;
		}
		
		switch (desc->wireformat[i]) {
		case KNOT_RDATA_WF_COMPRESSED_DNAME:
		case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
		case KNOT_RDATA_WF_LITERAL_DNAME: {
			knot_dname_t *dname =
				knot_rdata_item(rdata, i)->dname;
			if (size + rdlength + dname->size > max_size) {
				return KNOT_ESPACE;
			}

			// save whole domain name
			memcpy(*pos, knot_dname_name(dname), 
			       knot_dname_size(dname));
			fprintf(stderr, "Uncompressed dname size: %d\n",
			        knot_dname_size(dname));
			*pos += knot_dname_size(dname);
			rdlength += knot_dname_size(dname);
//			compr->wire_pos += dname->size;
			break;
		}
		default: {
			uint16_t *raw_data =
				knot_rdata_item(rdata, i)->raw_data;

			if (size + rdlength + raw_data[0] > max_size) {
				return KNOT_ESPACE;
			}

			// copy just the rdata item data (without size)
			memcpy(*pos, raw_data + 1, raw_data[0]);
			fprintf(stderr, "Raw data size: %d\n", raw_data[0]);
			*pos += raw_data[0];
			rdlength += raw_data[0];
//			compr->wire_pos += raw_data[0];
			break;
		}
		}
	}
	
	fprintf(stderr, "Max size: %zu, size: %d\n", max_size, size);

	assert(size + rdlength <= max_size);
	size += rdlength;
	knot_wire_write_u16(rdlength_pos, rdlength);

	return size;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire, size_t *size,
                       int *rr_count)
{
	// if no RDATA in RRSet, return
	if (rrset->rdata == NULL) {
		*size = 0;
		*rr_count = 0;
		return KNOT_EOK;
	}
	

	uint8_t *pos = wire;
	int rrs = 0;
	short rrset_size = 0;

	const knot_rdata_t *rdata = rrset->rdata;
	do {
		int ret = knot_rrset_rr_to_wire(rrset, rdata, &pos, 
		                                *size - rrset_size);

		assert(ret != 0);

		if (ret < 0) {
			// some RR didn't fit in, so no RRs should be used
			// TODO: remove last entries from compression table
			fprintf(stderr, "Some RR didn't fit in.\n");
			return KNOT_ESPACE;
		}

		fprintf(stderr, "RR of size %d added.\n", ret);
		rrset_size += ret;
		++rrs;
	} while ((rdata = knot_rrset_rdata_next(rrset, rdata)) != NULL);

	// the whole RRSet did fit in
	assert(rrset_size <= *size);
	assert(pos - wire == rrset_size);
	*size = rrset_size;

	fprintf(stderr, "  Size after: %zu\n", *size);

	*rr_count = rrs;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_compare(const knot_rrset_t *r1,
                       const knot_rrset_t *r2,
                       knot_rrset_compare_type_t cmp)
{
	if (cmp == KNOT_RRSET_COMPARE_PTR) {
		return (r1 == r2);
	}

	int res = ((r1->rclass == r2->rclass)
	           && (r1->type == r2->type)
	           && (r1->ttl == r2->ttl)
	           && knot_dname_compare(r1->owner, r2->owner) == 0);

	if (cmp == KNOT_RRSET_COMPARE_WHOLE && res) {
		res = knot_rrset_compare_rdata(r1, r2);
		if (res < 0) {
			return 0;
		}
	}

	return res;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_deep_copy(const knot_rrset_t *from, knot_rrset_t **to)
{
	if (from == NULL || to == NULL) {
		return KNOT_EBADARG;
	}

	int ret;

	*to = (knot_rrset_t *)calloc(1, sizeof(knot_rrset_t));
	CHECK_ALLOC_LOG(*to, KNOT_ENOMEM);

	(*to)->owner = knot_dname_deep_copy(from->owner);
	(*to)->rclass = from->rclass;
	(*to)->ttl = from->ttl;
	(*to)->type = from->type;
	if (from->rrsigs != NULL) {
		ret = knot_rrset_deep_copy(from->rrsigs, &(*to)->rrsigs);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(to, 1, 0, 0);
			return ret;
		}
	}
	assert((*to)->rrsigs == NULL || from->rrsigs != NULL);

	const knot_rdata_t *rdata = knot_rrset_rdata(from);

	/*! \note Order of RDATA will be reversed. */
	while (rdata != NULL) {
		ret = knot_rrset_add_rdata(*to, knot_rdata_deep_copy(rdata,
		                           knot_rrset_type(from)));
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(to, 1, 1, 1);
			return ret;
		}
		rdata = knot_rrset_rdata_next(from, rdata);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_shallow_copy(const knot_rrset_t *from, knot_rrset_t **to)
{
	*to = (knot_rrset_t *)malloc(sizeof(knot_rrset_t));
	CHECK_ALLOC_LOG(*to, KNOT_ENOMEM);
	
	memcpy(*to, from, sizeof(knot_rrset_t));

	/* Retain owner. */
	knot_dname_retain((*to)->owner);
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_rrset_free(knot_rrset_t **rrset)
{
	if (rrset == NULL || *rrset == NULL) {
		return;
	}

	/*! \todo Shouldn't we always release owner reference? */
	knot_dname_release((*rrset)->owner);

	free(*rrset);
	*rrset = NULL;
}

/*----------------------------------------------------------------------------*/

void knot_rrset_deep_free(knot_rrset_t **rrset, int free_owner,
                            int free_rdata, int free_rdata_dnames)
{
	if (rrset == NULL || *rrset == NULL) {
		return;
	}

	if (free_rdata) {
		knot_rdata_t *tmp_rdata;
		knot_rdata_t *next_rdata;
		tmp_rdata = (*rrset)->rdata;

		while ((tmp_rdata != NULL)
		       && (tmp_rdata->next != (*rrset)->rdata)
		       && (tmp_rdata->next != NULL)) {
			next_rdata = tmp_rdata->next;
			knot_rdata_deep_free(&tmp_rdata, (*rrset)->type,
					       free_rdata_dnames);
			tmp_rdata = next_rdata;
		}

		assert(tmp_rdata == NULL
		       || tmp_rdata->next == (*rrset)->rdata);

		knot_rdata_deep_free(&tmp_rdata, (*rrset)->type,
		                       free_rdata_dnames);
	}

	// RRSIGs should have the same owner as this RRSet, so do not delete it
	if ((*rrset)->rrsigs != NULL) {
		knot_rrset_deep_free(&(*rrset)->rrsigs, 0, 1,
		                       free_rdata_dnames);
	}

	/*! \todo Release owner every time? */
	//if (free_owner) {
		knot_dname_release((*rrset)->owner);
	//}

	free(*rrset);
	*rrset = NULL;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_merge(void **r1, void **r2)
{
	knot_rrset_t *rrset1 = (knot_rrset_t *)(*r1);
	knot_rrset_t *rrset2 = (knot_rrset_t *)(*r2);

	if ((knot_dname_compare(rrset1->owner, rrset2->owner) != 0)
	    || rrset1->rclass != rrset2->rclass
	    || rrset1->type != rrset2->type
	    || rrset1->ttl != rrset2->ttl) {
		return KNOT_EBADARG;
	}

	// add all RDATAs from rrset2 to rrset1 (i.e. concatenate linked lists)

	// no RDATA in RRSet 1
	assert(rrset1 && rrset2);
	if (rrset1->rdata == NULL) {
		rrset1->rdata = rrset2->rdata;
		return KNOT_EOK;
	}

	knot_rdata_t *tmp_rdata = rrset1->rdata;

	if (!tmp_rdata) {
		return KNOT_EOK;
	}

	while (tmp_rdata->next != rrset1->rdata) {
		tmp_rdata = tmp_rdata->next;
	}

	tmp_rdata->next = rrset2->rdata;

	tmp_rdata = rrset2->rdata; //maybe unnecessary, but is clearer

	while (tmp_rdata->next != rrset2->rdata) {
		tmp_rdata = tmp_rdata->next;
	}

	tmp_rdata->next = rrset1->rdata;

	return KNOT_EOK;
}
