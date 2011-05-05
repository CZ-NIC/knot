#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/rdata.h"
#include "dnslib/descriptor.h"
#include "dnslib/dname.h"
#include "dnslib/error.h"
#include "dnslib/node.h"

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
static int dnslib_rdata_compare_binary(const uint8_t *d1, const uint8_t *d2,
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
static const dnslib_dname_t *dnslib_rdata_mx_name(const dnslib_rdata_t *rdata)
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
static const dnslib_dname_t *dnslib_rdata_ns_name(const dnslib_rdata_t *rdata)
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
static const dnslib_dname_t *dnslib_rdata_srv_name(const dnslib_rdata_t *rdata)
{
	if (rdata->count < 4) {
		return NULL;
	}
	return rdata->items[3].dname;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_rdata_t *dnslib_rdata_new()
{
	dnslib_rdata_t *rdata =
		(dnslib_rdata_t *)malloc(sizeof(dnslib_rdata_t));
	if (rdata == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	rdata->items = NULL;
	rdata->count = 0;

	return rdata;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_from_wire(dnslib_rdata_t *rdata, const uint8_t *wire,
                           size_t *pos, size_t total_size, size_t rdlength,
                           const dnslib_rrtype_descriptor_t *desc)
{
	int i = 0;
	uint8_t item_type;
	size_t parsed = 0;

	dnslib_rdata_item_t *items = (dnslib_rdata_item_t *)malloc(
	                            desc->length * sizeof(dnslib_rdata_item_t));
	CHECK_ALLOC_LOG(items, DNSLIB_ENOMEM);

	size_t item_size;
	uint8_t gateway_type = 0;  // only to handle IPSECKEY record
	dnslib_dname_t *dname;

	while (parsed < rdlength && i < desc->length) {
		item_type = desc->wireformat[i];
		item_size = 0;

		switch (item_type) {
		case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_LITERAL_DNAME:
			dname = dnslib_dname_parse_from_wire(
				wire, pos, total_size, NULL);
			if (dname == NULL) {
				free(items);
				return DNSLIB_ERROR;
			}
			items[i].dname = dname;
			*pos += dname->size;
			parsed += dname->size;
			break;
		case DNSLIB_RDATA_WF_BYTE:
			if (desc->type == DNSLIB_RRTYPE_IPSECKEY && i == 1) {
				gateway_type = *(wire + *pos);
			}
			item_size = 1;
			break;
		case DNSLIB_RDATA_WF_SHORT:
			item_size = 2;
			break;
		case DNSLIB_RDATA_WF_LONG:
			item_size = 4;
			break;
		case DNSLIB_RDATA_WF_TEXT:
			break;
		case DNSLIB_RDATA_WF_A:
			item_size = 4;
			break;
		case DNSLIB_RDATA_WF_AAAA:
			item_size = 16;
			break;
		case DNSLIB_RDATA_WF_BINARY:
			// the rest of the RDATA is this item
			item_size = rdlength - parsed;
			break;
		case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
			item_size = *(wire + *pos);
			break;
		case DNSLIB_RDATA_WF_APL:
			// WTF? what to do with this??
			break;
		case DNSLIB_RDATA_WF_IPSECGATEWAY:
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
				dname =
					dnslib_dname_parse_from_wire(
					           wire, pos, total_size, NULL);
				if (dname == NULL) {
					return DNSLIB_ERROR;
				}
				items[i].dname = dname;
				*pos += dname->size;
				parsed += dname->size;
				break;
			default:
				assert(0);
			}

			break;
		default:
			return DNSLIB_EMALF;

		}

		if (item_size != 0) {
			if (parsed + item_size > rdlength) {
				free(items);
				return DNSLIB_EFEWDATA;
			}

			items[i].raw_data = (uint16_t *)malloc(item_size);
			if (items[i].raw_data == NULL) {
				free(items);
				return DNSLIB_ENOMEM;
			}
			memcpy(items[i].raw_data, wire + *pos, item_size);
			*pos += item_size;
			parsed += item_size;
		}

		++i;
	}

	// all items are parsed, insert into the RDATA
	int rc;
	rc = dnslib_rdata_set_items(rdata, items, i);
	free(items);
	return rc;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_set_item(dnslib_rdata_t *rdata, uint pos,
			  dnslib_rdata_item_t item)
{
	if (pos >= rdata->count) {
		return DNSLIB_EBADARG;
	}
	rdata->items[pos] = item; // this should copy the union; or use memcpy?
	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_set_items(dnslib_rdata_t *rdata,
			   const dnslib_rdata_item_t *items, uint count)
{
	if (rdata == NULL || items == NULL || count == 0 ||
	    rdata->items != NULL) {
		return DNSLIB_EBADARG;
	}

	assert(rdata->count == 0);
	if ((rdata->items = (dnslib_rdata_item_t *)malloc(
			     count * sizeof(dnslib_rdata_item_t))) == NULL) {
		ERR_ALLOC_FAILED;
		return DNSLIB_ENOMEM;
	}

	memcpy(rdata->items, items, count * sizeof(dnslib_rdata_item_t));
	rdata->count = count;

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

const dnslib_rdata_item_t *dnslib_rdata_item(const dnslib_rdata_t *rdata,
					     uint pos)
{
	if (pos >= rdata->count) {
		return NULL;
	} else {
		return &rdata->items[pos];
	}
}

/*----------------------------------------------------------------------------*/

dnslib_rdata_item_t *dnslib_rdata_get_item(const dnslib_rdata_t *rdata,
					   uint pos)
{
	if (pos >= rdata->count) {
		return NULL;
	} else {
		return &rdata->items[pos];
	}
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_item_set_dname(dnslib_rdata_t *rdata, uint pos,
				dnslib_dname_t *dname)
{
	if (pos >= rdata->count) {
		return DNSLIB_EBADARG;
	}

	rdata->items[pos].dname = dname;

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_item_set_raw_data(dnslib_rdata_t *rdata, uint pos,
				   uint16_t *raw_data)
{
	if (pos >= rdata->count) {
		return DNSLIB_EBADARG;
	}

	rdata->items[pos].raw_data = raw_data;

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

void dnslib_rdata_free(dnslib_rdata_t **rdata)
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

void dnslib_rdata_deep_free(dnslib_rdata_t **rdata, uint type,
			    int free_all_dnames)
{
	if (rdata == NULL || *rdata == NULL) {
		return;
	}

	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
	assert(desc != NULL);

	assert((*rdata)->count <= desc->length);

	for (int i = 0; i < (*rdata)->count; i++) {
		if (&((*rdata)->items[i]) == NULL) {
			continue;
		}
		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME
		    || desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME
		    || desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME ) {
			if (((*rdata)->items[i].dname != NULL) &&
			    (free_all_dnames ||
			     (((*rdata)->items[i].dname->node == NULL) ||
			     ((*rdata)->items[i].dname->node->owner !=
			      (*rdata)->items[i].dname)))) {

				dnslib_dname_free(&(*rdata)->items[i].dname);
			}
		} else {
			free((*rdata)->items[i].raw_data);
		}
	}

	if ((*rdata)->items) {
		free((*rdata)->items);
	}
	free(*rdata);
	*rdata = NULL;
}

/*----------------------------------------------------------------------------*/

//uint dnslib_rdata_wire_size(const dnslib_rdata_t *rdata,
//                            const uint8_t *format)
//{
//	uint size = 0;

//	for (int i = 0; i < rdata->count; ++i) {
//		switch (format[i]) {
//		case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
//		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
//		case DNSLIB_RDATA_WF_LITERAL_DNAME:
//			size += dnslib_dname_size(rdata->items[i].dname);
//			break;
//		case DNSLIB_RDATA_WF_BYTE:
//			size += 1;
//			break;
//		case DNSLIB_RDATA_WF_SHORT:
//			size += 2;
//			break;
//		case DNSLIB_RDATA_WF_LONG:
//			size += 4;
//			break;
//		case DNSLIB_RDATA_WF_A:
//			size += 4;
//			break;
//		case DNSLIB_RDATA_WF_AAAA:
//			size += 16;
//			break;
//		case DNSLIB_RDATA_WF_BINARY:
//		case DNSLIB_RDATA_WF_APL:            // saved as binary
//		case DNSLIB_RDATA_WF_IPSECGATEWAY:   // saved as binary
//			size += rdata->items[i].raw_data[0];
//			break;
//		case DNSLIB_RDATA_WF_TEXT:
//		case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
//			size += rdata->items[i].raw_data[0] + 1;
//			break;
//		default:
//			assert(0);
//		}
//	}
//	return size;
//}

/*----------------------------------------------------------------------------*/

//int dnslib_rdata_to_wire(const dnslib_rdata_t *rdata, const uint8_t *format,
//                         uint8_t *buffer, uint buf_size)
//{
//	uint copied = 0;
//	uint8_t tmp[DNSLIB_MAX_RDATA_WIRE_SIZE];
//	uint8_t *to = tmp;

//	for (int i = 0; i < rdata->count; ++i) {
//		assert(copied < DNSLIB_MAX_RDATA_WIRE_SIZE);

//		const uint8_t *from = (uint8_t *)rdata->items[i].raw_data;
//		uint size = 0;

//		switch (format[i]) {
//		case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
//		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
//		case DNSLIB_RDATA_WF_LITERAL_DNAME:
//			size = dnslib_dname_size(rdata->items[i].dname);
//			from = dnslib_dname_name(rdata->items[i].dname);

//			break;
//		case DNSLIB_RDATA_WF_BYTE:
//			size = 1;
//			break;
//		case DNSLIB_RDATA_WF_SHORT:
//			size = 2;
//			break;
//		case DNSLIB_RDATA_WF_LONG:
//			size = 4;
//			break;
//		case DNSLIB_RDATA_WF_A:
//			size = 4;
//			break;
//		case DNSLIB_RDATA_WF_AAAA:
//			size = 16;
//			break;
//		case DNSLIB_RDATA_WF_TEXT:
//		case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
//			// size stored in the first two bytes, but in little
//			// endian and we need only the lower byte from it
//			*to = *from; // lower byte is the first in little endian
//			to += 1;
//		case DNSLIB_RDATA_WF_BINARY:
//		case DNSLIB_RDATA_WF_APL:            // saved as binary
//		case DNSLIB_RDATA_WF_IPSECGATEWAY:   // saved as binary
//			// size stored in the first two bytes, those bytes
//			// must not be copied
//			size = rdata->items[i].raw_data[0];
//			from += 2; // skip the first two bytes
//			break;
//		default:
//			assert(0);
//		}

//		assert(size != 0);
//		assert(copied + size < DNSLIB_MAX_RDATA_WIRE_SIZE);

//		memcpy(to, from, size);
//		to += size;
//		copied += size;
//	}

//	if (copied > buf_size) {
//		debug_dnslib_rdata("Not enough place allocated for function "
//		            "dnslib_rdata_to_wire(). Allocated %u, need %u\n",
//		            buf_size, copied);
//		return -1;
//	}

//	memcpy(buffer, tmp, copied);
//	return 0;
//}

/*----------------------------------------------------------------------------*/

dnslib_rdata_t *dnslib_rdata_copy(const dnslib_rdata_t *rdata, uint16_t type)
{
	dnslib_rdata_t *copy = dnslib_rdata_new();
	CHECK_ALLOC_LOG(copy, NULL);


	if ((copy->items = (dnslib_rdata_item_t *)malloc(
			rdata->count * sizeof(dnslib_rdata_item_t))) == NULL) {
		dnslib_rdata_free(&copy);
		ERR_ALLOC_FAILED;
		return NULL;
	}

	copy->count = rdata->count;

	dnslib_rrtype_descriptor_t *d = dnslib_rrtype_descriptor_by_type(type);

	assert(copy->count <= d->length);

	// copy all items one by one
	for (int i = 0; i < copy->count; ++i) {
		if (d->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME
		    || d->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME
		    || d->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME) {
			copy->items[i].dname =
				dnslib_dname_copy(rdata->items[i].dname);
		} else {
			copy->items[i].raw_data = (uint16_t *)malloc(
					rdata->items[i].raw_data[0] + 2);
			if (copy->items[i].raw_data == NULL) {
				dnslib_rdata_deep_free(&copy, type, 1);
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

int dnslib_rdata_compare(const dnslib_rdata_t *r1, const dnslib_rdata_t *r2,
			 const uint8_t *format)
{
	uint count = (r1->count < r2->count) ? r1->count : r2->count;

	int cmp = 0;

	for (int i = 0; i < count; ++i) {
		const uint8_t *data1, *data2;
		int size1, size2;

		if (format[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		    format[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
		    format[i] == DNSLIB_RDATA_WF_LITERAL_DNAME) {
			data1 = dnslib_dname_name(r1->items[i].dname);
			data2 = dnslib_dname_name(r2->items[i].dname);
			size1 = dnslib_dname_size(r2->items[i].dname);
			size2 = dnslib_dname_size(r2->items[i].dname);
		} else {
			data1 = (uint8_t *)(r1->items[i].raw_data + 1);
			data2 = (uint8_t *)(r2->items[i].raw_data + 1);
			size1 = r1->items[i].raw_data[0];
			size2 = r1->items[i].raw_data[0];
		}

		cmp = dnslib_rdata_compare_binary(data1, data2, size1, size2);

		if (cmp != 0) {
			return cmp;
		}
	}

	assert(cmp == 0);
	return 0;
}

/*----------------------------------------------------------------------------*/

const dnslib_dname_t *dnslib_rdata_cname_name(const dnslib_rdata_t *rdata)
{
	if (rdata->count < 1) {
		return NULL;
	}
	return rdata->items[0].dname;
}

/*----------------------------------------------------------------------------*/

const dnslib_dname_t *dnslib_rdata_dname_target(const dnslib_rdata_t *rdata)
{
	if (rdata->count < 1) {
		return NULL;
	}
	return rdata->items[0].dname;
}

/*----------------------------------------------------------------------------*/

const dnslib_dname_t *dnslib_rdata_get_name(const dnslib_rdata_t *rdata,
					    uint16_t type)
{
	// iterate over the rdata items or act as if we knew where the name is?

	switch (type) {
	case DNSLIB_RRTYPE_NS:
		return dnslib_rdata_ns_name(rdata);
	case DNSLIB_RRTYPE_MX:
		return dnslib_rdata_mx_name(rdata);
	case DNSLIB_RRTYPE_SRV:
		return dnslib_rdata_srv_name(rdata);
	case DNSLIB_RRTYPE_CNAME:
		return dnslib_rdata_cname_name(rdata);
	}

	return NULL;
}
