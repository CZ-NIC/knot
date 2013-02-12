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
#include <string.h>
#include <stdio.h>

#include "common.h"
#include "rdata.h"
#include "util/descriptor.h"
#include "dname.h"
#include "zone/node.h"
#include "util/utils.h"
#include "util/debug.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Compares two RDATA items as binary data.
 *
 * \param d1 First item.
 * \param d2 Second item.
 * \param count1 Size of the first item in bytes. If set to < 0, the size will
 *               be taken from the first two bytes of \a d1.
 * \param count2 Size of the second item in bytes. If set to < 0, the size will
 *               be taken from the first two bytes of \a d2.
 *
 * \retval 0 if the items are identical.
 * \retval < 0 if \a d1 goes before \a d2 in canonical order.
 * \retval > 0 if \a d1 goes after \a d2 in canonical order.
 */
static int knot_rdata_compare_binary(const uint8_t *d1, const uint8_t *d2,
				       int count1, int count2)
{
	int i1 = 0, i2 = 0;

	// length stored in the first octet
	if (count1 < 0) {
		// take count from the first two bytes
		count1 = (int)(*(uint16_t *)d1);
		// and start from the third byte
		i1 = 2;
	}
	if (count2 < 0) {  // dtto
		count2 = (int)(*(uint16_t *)d2);
		i2 = 2;
	}


	while (i1 < count1 && i2 < count2 && d1[i1] == d2[i2]) {
		++i1;
		++i2;
	}

	if (i1 == count1 && i2 == count2) {
		return 0;
	}

	if (i1 == count1 && i2 < count2) {
		return -1;
	} else if (i2 == count2 && i1 < count1) {
		return 1;
	} else {
		assert(i1 < count1 && i2 < count2);
		return (d1[i1] < d2[i2]) ? -1 : 1;
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Retrieves the domain name from MX RDATA.
 *
 * \note This is only convenience function. It does not (and cannot) check if
 *       the given RDATA is of the right type, so it always returns the second
 *       RDATA item, even if it is not a domain name.
 *
 * \param rdata RDATA to get the MX domain name from.
 *
 * \return MX domain name stored in \a rdata or NULL if \a rdata has less than 2
 *         items.
 */
static const knot_dname_t *knot_rdata_mx_name(const knot_rdata_t *rdata)
{
	if (rdata->count < 2) {
		return NULL;
	}
	return rdata->items[1].dname;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Retrieves the domain name from NS RDATA.
 *
 * \note This is only convenience function. It does not (and cannot) check if
 *       the given RDATA is of the right type, so it always returns the first
 *       RDATA item, even if it is not a domain name.
 *
 * \param rdata RDATA to get the NS domain name from.
 *
 * \return NS domain name stored in \a rdata or NULL if \a rdata has no items.
 */
static const knot_dname_t *knot_rdata_ns_name(const knot_rdata_t *rdata)
{
	if (rdata->count < 1) {
		return NULL;
	}
	return rdata->items[0].dname;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Retrieves the domain name from SRV RDATA.
 *
 * \note This is only convenience function. It does not (and cannot) check if
 *       the given RDATA is of the right type, so it always returns the fourth
 *       RDATA item, even if it is not a domain name.
 *
 * \param rdata RDATA to get the SRV domain name from.
 *
 * \return SRV domain name stored in \a rdata or NULL if \a rdata has less than
 *         4 items.
 */
static const knot_dname_t *knot_rdata_srv_name(const knot_rdata_t *rdata)
{
	if (rdata->count < 4) {
		return NULL;
	}
	return rdata->items[3].dname;
}

/*----------------------------------------------------------------------------*/

static void knot_rdata_free_items(knot_rdata_item_t *items, unsigned int count,
                                  uint type, int free_all_dnames)
{
	if (items == NULL) {
		return;
	}

	knot_rrtype_descriptor_t *desc = knot_rrtype_descriptor_by_type(type);
	assert(desc != NULL);

	assert(count <= desc->length);

	for (int i = 0; i < count; i++) {
		if (&(items[i]) == NULL) {
			continue;
		}
		if (desc->wireformat[i] == KNOT_RDATA_WF_COMPRESSED_DNAME
		    || desc->wireformat[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME
		    || desc->wireformat[i] == KNOT_RDATA_WF_LITERAL_DNAME) {
			if ((items[i].dname != NULL)) {
				/*! \todo This is hack to prevent memory errors,
				 *        as the rdata_set_items() cannot determine
				 *        items type and so cannot increment
				 *        reference count in case of dname type.
				 *        Free would then release dnames that
				 *        aren't referenced by the rdata.
				 */
				if (free_all_dnames) {
					knot_dname_release(items[i].dname);
				}
			}
		} else {
			free(items[i].raw_data);
		}
	}

	free(items);
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_rdata_t *knot_rdata_new()
{
	knot_rdata_t *rdata =
		(knot_rdata_t *)malloc(sizeof(knot_rdata_t));
	if (rdata == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	rdata->items = NULL;
	rdata->count = 0;
	rdata->next = NULL;

	return rdata;
}

/*----------------------------------------------------------------------------*/

int knot_rdata_from_wire(knot_rdata_t *rdata, const uint8_t *wire,
                         size_t *pos, size_t total_size, size_t rdlength,
                         const knot_rrtype_descriptor_t *desc)
{
	int i = 0;
	uint8_t item_type;
	size_t parsed = 0;

	if (rdlength == 0) {
		rdata->items = NULL;
		return KNOT_EOK;
	}

	knot_rdata_item_t *items = (knot_rdata_item_t *)malloc(
	                            desc->length * sizeof(knot_rdata_item_t));
	CHECK_ALLOC_LOG(items, KNOT_ENOMEM);

	size_t item_size = 0;
	uint8_t gateway_type = 0;  // only to handle IPSECKEY record
	knot_dname_t *dname = NULL;

	while (i < desc->length && (desc->fixed_items || parsed < rdlength)) {
		
		item_type = desc->wireformat[i];
		item_size = 0;

		size_t pos2;

		switch (item_type) {
		case KNOT_RDATA_WF_COMPRESSED_DNAME:
		case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
		case KNOT_RDATA_WF_LITERAL_DNAME:
			pos2 = *pos;
			dname = knot_dname_parse_from_wire(
				wire, &pos2, total_size, NULL, NULL);
			if (dname == NULL) {
				free(items);
				return KNOT_ERROR;
			}
			items[i].dname = dname;
			parsed += pos2 - *pos;
			*pos = pos2;
			dname = 0;
			break;
		case KNOT_RDATA_WF_BYTE:
			if (desc->type == KNOT_RRTYPE_IPSECKEY && i == 1) {
				gateway_type = *(wire + *pos);
			}
			item_size = 1;
			break;
		case KNOT_RDATA_WF_SHORT:
			item_size = 2;
			break;
		case KNOT_RDATA_WF_LONG:
			item_size = 4;
			break;
		case KNOT_RDATA_WF_UINT48:
			item_size = 6;
			break;
		case KNOT_RDATA_WF_TEXT:
			item_size = rdlength - parsed;
			break;
		case KNOT_RDATA_WF_TEXT_SINGLE:
			item_size = *(wire + *pos) + 1;
			break;
		case KNOT_RDATA_WF_A:
			item_size = 4;
			break;
		case KNOT_RDATA_WF_AAAA:
			item_size = 16;
			break;
		case KNOT_RDATA_WF_BINARY:
			item_size = rdlength - parsed;
			break;
		case KNOT_RDATA_WF_BINARYWITHLENGTH:
			item_size = *(wire + *pos) + 1;
			break;
		case KNOT_RDATA_WF_BINARYWITHSHORT:
			item_size = knot_wire_read_u16(wire + *pos) + 2;
			break;
		case KNOT_RDATA_WF_APL:
			// WTF? what to do with this??
			// Same as TXT, I guess.
			item_size = rdlength - parsed;
			break;
		case KNOT_RDATA_WF_IPSECGATEWAY:
			// determine size based on the 'gateway type' field
			switch (gateway_type) {
			case 0:
				item_size = 0;
				break;
			case 1:
				item_size = 4;
				break;
			case 2:
				item_size = 16;
				break;
			case 3:
				pos2 = *pos;
				dname = knot_dname_parse_from_wire(
					   wire, &pos2, total_size, NULL, NULL);
				if (dname == NULL) {
					knot_rdata_free_items(items, i,
					                      desc->type, 1);
					return KNOT_ERROR;
				}
			
				items[i].raw_data = (uint16_t *)malloc(
						knot_dname_size(dname) + 2);
				if (items[i].raw_data == NULL) {
					knot_dname_free(&dname);
					knot_rdata_free_items(items, i,
					                      desc->type, 1);
					return KNOT_ENOMEM;
				}
				
				items[i].raw_data[0] = knot_dname_size(dname);
				memcpy((uint8_t *)(items[i].raw_data + 1),
				       knot_dname_name(dname),
				       knot_dname_size(dname));

				parsed += pos2 - *pos;

				*pos = pos2;
				knot_dname_free(&dname);
				
				// continue with next item
				++i;
				continue;
				
				break;
			default:
				assert(0);
			}

			break;
		default:
			knot_rdata_free_items(items, i,
			                      desc->type, 1);
			return KNOT_EMALF;

		}

		if (item_size != 0) {
			if (parsed + item_size > rdlength) {
				knot_rdata_free_items(items, i,
				                      desc->type, 1);
				return KNOT_EFEWDATA;
			}

			items[i].raw_data = (uint16_t *)malloc(item_size + 2);
			if (items[i].raw_data == NULL) {
				knot_rdata_free_items(items, i,
				                      desc->type, 1);
				return KNOT_ENOMEM;
			}
			memcpy(items[i].raw_data, &item_size, 2);
			memcpy(items[i].raw_data + 1, wire + *pos, item_size);
			*pos += item_size;
			parsed += item_size;
		} else if (item_type == KNOT_RDATA_WF_BINARY) {
			// in this case we are at the end of the RDATA
			// and should create an empty RDATA item
			items[i].raw_data = (uint16_t *)malloc(2);
			if (items[i].raw_data == NULL) {
				knot_rdata_free_items(items, i,
				                      desc->type, 1);
				return KNOT_ENOMEM;
			}
			memcpy(items[i].raw_data, &item_size, 2);
		} else if (item_type != KNOT_RDATA_WF_COMPRESSED_DNAME
		           && item_type != KNOT_RDATA_WF_UNCOMPRESSED_DNAME
		           && item_type != KNOT_RDATA_WF_LITERAL_DNAME) {
				assert(0);
		}

		++i;
	}

	assert(!desc->fixed_items || i == desc->length);

	// all items are parsed, insert into the RDATA
	int rc;
	rc = knot_rdata_set_items(rdata, items, i);
	
	for (int j = 0; j < i; ++j) {
		assert(rdata->items[j].raw_data != NULL);
	}
	
	free(items);
	return rc;
}

/*----------------------------------------------------------------------------*/

int knot_rdata_set_item(knot_rdata_t *rdata, uint pos,
			  knot_rdata_item_t item)
{
	if (pos >= rdata->count) {
		return KNOT_EINVAL;
	}

	/*! \todo As in set_items() we should increment refcounter for dnames,
	 *        but we don't know the item type.
	 */

	rdata->items[pos] = item; // this should copy the union; or use memcpy?
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

unsigned int knot_rdata_item_count(const knot_rdata_t *rdata)
{
	return rdata->count;
}

/*----------------------------------------------------------------------------*/

int knot_rdata_set_items(knot_rdata_t *rdata,
			   const knot_rdata_item_t *items, uint count)
{
	if (rdata == NULL || items == NULL || count == 0 ||
	    rdata->items != NULL) {
		return KNOT_EINVAL;
	}

	assert(rdata->count == 0);
	if ((rdata->items = (knot_rdata_item_t *)malloc(
			     count * sizeof(knot_rdata_item_t))) == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	memcpy(rdata->items, items, count * sizeof(knot_rdata_item_t));
	rdata->count = count;

	/*! \todo Cannot determine items type, so the dname
	 *        refcounters should be increased in caller.
	 */

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

const knot_rdata_item_t *knot_rdata_item(const knot_rdata_t *rdata,
					     uint pos)
{
	if (pos >= rdata->count) {
		return NULL;
	} else {
		return &rdata->items[pos];
	}
}

/*----------------------------------------------------------------------------*/

knot_rdata_item_t *knot_rdata_get_item(const knot_rdata_t *rdata,
					   uint pos)
{
	if (pos >= rdata->count) {
		return NULL;
	} else {
		return &rdata->items[pos];
	}
}

/*----------------------------------------------------------------------------*/

int knot_rdata_item_set_dname(knot_rdata_t *rdata, uint pos,
				knot_dname_t *dname)
{
	if (pos >= rdata->count) {
		return KNOT_EINVAL;
	}

	/* Retain dname. */
	knot_dname_retain(dname);

	rdata->items[pos].dname = dname;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_rdata_item_set_raw_data(knot_rdata_t *rdata, uint pos,
				   uint16_t *raw_data)
{
	if (pos >= rdata->count) {
		return KNOT_EINVAL;
	}

	rdata->items[pos].raw_data = raw_data;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_rdata_count(const knot_rdata_t *rdata)
{
	if (rdata == NULL) {
		return 0;
	}

	int count = 1;
	const knot_rdata_t *r = rdata;

	while (r->next != NULL && r->next != rdata) {
		r = r->next;
		++count;
	}

	return count;
}

/*----------------------------------------------------------------------------*/

void knot_rdata_free(knot_rdata_t **rdata)
{
	if (rdata == NULL || *rdata == NULL) {
		return;
	}

	if ((*rdata)->items) {
		free((*rdata)->items);
	}
	free(*rdata);
	*rdata = NULL;
}

/*----------------------------------------------------------------------------*/

void knot_rdata_deep_free(knot_rdata_t **rdata, uint type,
			    int free_all_dnames)
{
	if (rdata == NULL || *rdata == NULL) {
		return;
	}

	if ((*rdata)->items != NULL) {
		knot_rdata_free_items((*rdata)->items, (*rdata)->count, type,
		                      free_all_dnames);
	}

	free(*rdata);
	*rdata = NULL;
}

/*----------------------------------------------------------------------------*/

knot_rdata_t *knot_rdata_deep_copy(const knot_rdata_t *rdata, 
                                       uint16_t type, int copy_dnames)
{
	knot_rdata_t *copy = knot_rdata_new();
	CHECK_ALLOC_LOG(copy, NULL);


	if ((copy->items = (knot_rdata_item_t *)malloc(
			rdata->count * sizeof(knot_rdata_item_t))) == NULL) {
		knot_rdata_free(&copy);
		ERR_ALLOC_FAILED;
		return NULL;
	}

	copy->count = rdata->count;

	knot_rrtype_descriptor_t *d = knot_rrtype_descriptor_by_type(type);

	assert(copy->count <= d->length);

	// copy all items one by one
	for (int i = 0; i < copy->count; ++i) {
		if (d->wireformat[i] == KNOT_RDATA_WF_COMPRESSED_DNAME
		    || d->wireformat[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME
		    || d->wireformat[i] == KNOT_RDATA_WF_LITERAL_DNAME) {
			if (copy_dnames) {
				copy->items[i].dname =
				    knot_dname_deep_copy(rdata->items[i].dname);
			} else {
				copy->items[i].dname = rdata->items[i].dname;
				knot_dname_retain(rdata->items[i].dname);
			}
		} else {
			copy->items[i].raw_data = (uint16_t *)malloc(
					rdata->items[i].raw_data[0] + 2);
			if (copy->items[i].raw_data == NULL) {
				knot_rdata_deep_free(&copy, type, 1);
				return NULL;
			}
			memcpy(copy->items[i].raw_data,
			       rdata->items[i].raw_data,
			       rdata->items[i].raw_data[0] + 2);
		}
	}

	return copy;
}

/*----------------------------------------------------------------------------*/

int knot_rdata_compare(const knot_rdata_t *r1, const knot_rdata_t *r2,
			 const uint8_t *format)
{
	uint count = (r1->count < r2->count) ? r1->count : r2->count;

	int cmp = 0;

	for (int i = 0; i < count; ++i) {
		if (format[i] == KNOT_RDATA_WF_COMPRESSED_DNAME ||
		    format[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
		    format[i] == KNOT_RDATA_WF_LITERAL_DNAME) {
			cmp = knot_dname_compare(r1->items[i].dname,
			                           r2->items[i].dname);
		} else {
			cmp = knot_rdata_compare_binary(
				(uint8_t *)(r1->items[i].raw_data + 1),
				(uint8_t *)(r2->items[i].raw_data + 1),
				r1->items[i].raw_data[0],
				r1->items[i].raw_data[0]);
		}

		if (cmp != 0) {
			return cmp;
		}
	}

	assert(cmp == 0);
	return 0;
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_rdata_cname_name(const knot_rdata_t *rdata)
{
	if (rdata->count < 1) {
		return NULL;
	}
	return rdata->items[0].dname;
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_rdata_dname_target(const knot_rdata_t *rdata)
{
	if (rdata->count < 1) {
		return NULL;
	}
	return rdata->items[0].dname;
}

/*---------------------------------------------------------------------------*/

const knot_dname_t *knot_rdata_get_name(const knot_rdata_t *rdata,
                                            uint16_t type)
{
	// iterate over the rdata items or act as if we knew where the name is?

	switch (type) {
	case KNOT_RRTYPE_NS:
		return knot_rdata_ns_name(rdata);
	case KNOT_RRTYPE_MX:
		return knot_rdata_mx_name(rdata);
	case KNOT_RRTYPE_SRV:
		return knot_rdata_srv_name(rdata);
	case KNOT_RRTYPE_CNAME:
		return knot_rdata_cname_name(rdata);
	}

	return NULL;
}

/*---------------------------------------------------------------------------*/
int64_t knot_rdata_soa_serial(const knot_rdata_t *rdata)
{
	if (!rdata) {
		return -1;
	}

	if (rdata->count < 3) {
		return -1;
	}

	// the number is in network byte order, transform it
	return knot_wire_read_u32((uint8_t *)(rdata->items[2].raw_data + 1));
}

/*---------------------------------------------------------------------------*/
void knot_rdata_soa_serial_set(knot_rdata_t *rdata, uint32_t serial)
{
	if (!rdata || rdata->count < 3) {
		return;
	}

	// the number is in network byte order, transform it
	knot_wire_write_u32((uint8_t *)(rdata->items[2].raw_data + 1),
	                    serial);
}

/*---------------------------------------------------------------------------*/

uint32_t knot_rdata_soa_refresh(const knot_rdata_t *rdata)
{
	if (!rdata) {
		return 0;
	}

	if (rdata->count < 4) {
		return 0;	/*! \todo Some other error value. */
	}

	// the number is in network byte order, transform it
	return knot_wire_read_u32((uint8_t *)(rdata->items[3].raw_data + 1));
}

/*---------------------------------------------------------------------------*/

uint32_t knot_rdata_soa_retry(const knot_rdata_t *rdata)
{
	if (!rdata) {
		return 0;
	}

	if (rdata->count < 5) {
		return 0;	/*! \todo Some other error value. */
	}

	// the number is in network byte order, transform it
	return knot_wire_read_u32((uint8_t *)(rdata->items[4].raw_data + 1));
}

/*---------------------------------------------------------------------------*/

uint32_t knot_rdata_soa_expire(const knot_rdata_t *rdata)
{
	if (!rdata) {
		return -1;
	}

	if (rdata->count < 6) {
		return 0;	/*! \todo Some other error value. */
	}

	// the number is in network byte order, transform it
	return knot_wire_read_u32((uint8_t *)(rdata->items[5].raw_data + 1));
}

/*---------------------------------------------------------------------------*/

uint32_t knot_rdata_soa_minimum(const knot_rdata_t *rdata)
{
	if (!rdata) {
		return -1;
	}

	if (rdata->count < 7) {
		return 0;	/*! \todo Some other error value. */
	}

	// the number is in network byte order, transform it
	return knot_wire_read_u32((uint8_t *)(rdata->items[6].raw_data + 1));
}

/*---------------------------------------------------------------------------*/

uint16_t knot_rdata_rrsig_type_covered(const knot_rdata_t *rdata)
{
	if (rdata->count < 1) {
		return 0;
	}

	return knot_wire_read_u16((uint8_t *)(rdata->items[0].raw_data + 1));
}

/*---------------------------------------------------------------------------*/

uint8_t knot_rdata_nsec3_algorithm(const knot_rdata_t *rdata)
{
	if (rdata->count < 1) {
		return 0;
	}
	
	return *((uint8_t *)(rdata->items[0].raw_data + 1));
}

/*---------------------------------------------------------------------------*/

uint16_t knot_rdata_nsec3_iterations(const knot_rdata_t *rdata)
{
	if (rdata->count < 3) {
		// this is actually valid value...what to return??
		return 0;
	}
	
	return knot_wire_read_u16((uint8_t *)(rdata->items[2].raw_data + 1));
}

/*---------------------------------------------------------------------------*/

uint8_t knot_rdata_nsec3_salt_length(const knot_rdata_t *rdata)
{
	if (rdata->count < 4) {
		return 0;
	}
	
	return *((uint8_t *)(rdata->items[3].raw_data + 1));
}

/*---------------------------------------------------------------------------*/

const uint8_t *knot_rdata_nsec3_salt(const knot_rdata_t *rdata)
{
	if (rdata->count < 4) {
		return NULL;
	}
	
	return ((uint8_t *)(rdata->items[3].raw_data + 1)) + 1;
}

/*----------------------------------------------------------------------------*/

uint8_t knot_rdata_ds_digest_type(const knot_rdata_t *rdata)
{
	if (rdata->count < 3) {
		return 0;
	}

	return *((uint8_t *)(rdata->items[2].raw_data + 1));
}

/*----------------------------------------------------------------------------*/

uint16_t knot_rdata_ds_digest_len(const knot_rdata_t *rdata)
{
	if (rdata->count < 4) {
		return 0;
	}

	return *(rdata->items[3].raw_data);
}

/*----------------------------------------------------------------------------*/

int knot_rdata_ds_check(const knot_rdata_t *rdata)
{
	// Check if the legth of the digest corresponds to the proper size of
	// the digest according to the given algorithm
	uint16_t len = knot_rdata_ds_digest_len(rdata);
	uint8_t type = knot_rdata_ds_digest_type(rdata);

	if (type == 0 || len == 0) {
		return KNOT_EINVAL;
	} else if (len != knot_ds_digest_length(type)) {
		return KNOT_EDSDIGESTLEN;
	} else {
		return KNOT_EOK;
	}
}
