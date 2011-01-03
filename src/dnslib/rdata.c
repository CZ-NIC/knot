#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "rdata.h"
#include "common.h"
#include "descriptor.h"
#include "dname.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static int dnslib_rdata_compare_binary(const uint8_t *d1, const uint8_t *d2,
                                       int count1, int count2)
{
	int i1 = 0, i2 = 0;

	// length stored in the first octet
	if (count1 < 0) {
		// take count from the first byte
		count1 = (int)d1[0];
		// and start from the second byte
		i1 = 1;
	}
	if (count2 < 0) {	// dtto
		count2 = (int)d2[0];
		i2 = 1;
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

int dnslib_rdata_set_item(dnslib_rdata_t *rdata, uint pos,
                          dnslib_rdata_item_t item)
{
	if (pos >= rdata->count) {
		return -1;
	}
	rdata->items[pos] = item; // this should copy the union; or use memcpy?
	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_set_items(dnslib_rdata_t *rdata,
                           const dnslib_rdata_item_t *items, uint count)
{
	if (rdata == NULL || items == NULL || count == 0) {
		return 1;
	}

	if (rdata->items != NULL) {	// not empty
		return -1;
	}

	assert(rdata->count == 0);
	if ((rdata->items = (dnslib_rdata_item_t *)malloc(
	                     count * sizeof(dnslib_rdata_item_t))) == NULL) {
		ERR_ALLOC_FAILED;
		return -2;
	}

	memcpy(rdata->items, items, count * sizeof(dnslib_rdata_item_t));
	rdata->count = count;

	return 0;
}

/*----------------------------------------------------------------------------*/

const dnslib_rdata_item_t *dnslib_rdata_get_item(const dnslib_rdata_t *rdata,
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
		return -1;
	}

	rdata->items[pos].dname = dname;

	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_item_set_raw_data(dnslib_rdata_t *rdata, uint pos,
                                   uint8_t *raw_data)
{
	if (pos >= rdata->count) {
		return -1;
	}

	rdata->items[pos].raw_data = raw_data;

	return 0;
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

void dnslib_rdata_deep_free(dnslib_rdata_t **rdata, uint type)
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
			    ((*rdata)->items[i].dname->node == NULL)) {
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

uint dnslib_rdata_wire_size(const dnslib_rdata_t *rdata,
                            const uint8_t *format)
{
	uint size = 0;

	for (int i = 0; i < rdata->count; ++i) {
		switch (format[i]) {
		case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_LITERAL_DNAME:
			size += dnslib_dname_size(rdata->items[i].dname);
			break;
		case DNSLIB_RDATA_WF_BYTE:
			size += 1;
			break;
		case DNSLIB_RDATA_WF_SHORT:
			size += 2;
			break;
		case DNSLIB_RDATA_WF_LONG:
			size += 4;
			break;
		case DNSLIB_RDATA_WF_A:
			size += 4;
			break;
		case DNSLIB_RDATA_WF_AAAA:
			size += 16;
			break;
		case DNSLIB_RDATA_WF_BINARY:
		case DNSLIB_RDATA_WF_APL:            // saved as binary
		case DNSLIB_RDATA_WF_IPSECGATEWAY:   // saved as binary
			size += rdata->items[i].raw_data[0];
			break;
		case DNSLIB_RDATA_WF_TEXT:
		case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
			size += rdata->items[i].raw_data[0] + 1;
			break;
		default:
			assert(0);
		}
	}
	return size;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_to_wire(const dnslib_rdata_t *rdata, const uint8_t *format,
                         uint8_t *buffer, uint buf_size)
{
	uint copied = 0;
	uint8_t tmp[DNSLIB_MAX_RDATA_WIRE_SIZE];
	uint8_t *to = tmp;

	for (int i = 0; i < rdata->count; ++i) {
		assert(copied < DNSLIB_MAX_RDATA_WIRE_SIZE);

		const uint8_t *from = rdata->items[i].raw_data;
		uint size = 0;

		switch (format[i]) {
		case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_LITERAL_DNAME:
			size = dnslib_dname_size(rdata->items[i].dname);
			from = dnslib_dname_name(rdata->items[i].dname);

			break;
		case DNSLIB_RDATA_WF_BYTE:
			size = 1;
			break;
		case DNSLIB_RDATA_WF_SHORT:
			size = 2;
			break;
		case DNSLIB_RDATA_WF_LONG:
			size = 4;
			break;
		case DNSLIB_RDATA_WF_A:
			size = 4;
			break;
		case DNSLIB_RDATA_WF_AAAA:
			size = 16;
			break;
		case DNSLIB_RDATA_WF_TEXT:
		case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
			// size stored in the first byte, but
			// the first byte also needs to be copied
			size = rdata->items[i].raw_data[0] + 1;
			break;
		case DNSLIB_RDATA_WF_BINARY:
		case DNSLIB_RDATA_WF_APL:            // saved as binary
		case DNSLIB_RDATA_WF_IPSECGATEWAY:   // saved as binary
			// size stored in the first byte, first
			// byte must not be copied
			size = rdata->items[i].raw_data[0];
			++from;
			break;
		default:
			assert(0);
		}

		assert(size != 0);
		assert(copied + size < DNSLIB_MAX_RDATA_WIRE_SIZE);

		memcpy(to, from, size);
		to += size;
		copied += size;
	}

	if (copied > buf_size) {
		log_warning("Not enough place allocated for function "
		            "dnslib_rdata_to_wire(). Allocated %u, need %u\n",
		            buf_size, copied);
		return -1;
	}

	memcpy(buffer, tmp, copied);
	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_compare(const dnslib_rdata_t *r1, const dnslib_rdata_t *r2,
                         const uint8_t *format)
{
	uint count = (r1->count < r2->count) ? r1->count : r2->count;

	int cmp = 0;

	for (int i = 0; i < count; ++i) {
		dnslib_rdata_item_t *item1 = &r1->items[i];
		dnslib_rdata_item_t *item2 = &r2->items[i];

		const uint8_t *data1 = r1->items[i].raw_data;
		const uint8_t *data2 = r2->items[i].raw_data;
		int size1, size2;

		switch (format[i]) {
		case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_LITERAL_DNAME:
			data1 = dnslib_dname_name(item1->dname);
			size1 = dnslib_dname_size(item1->dname);
			data2 = dnslib_dname_name(item2->dname);
			size2 = dnslib_dname_size(item2->dname);
			break;
		case DNSLIB_RDATA_WF_BYTE:
			size1 = size2 = 1;
			break;
		case DNSLIB_RDATA_WF_SHORT:
			size1 = size2 = 2;
			break;
		case DNSLIB_RDATA_WF_LONG:
			size1 = size2 = 4;
			break;
		case DNSLIB_RDATA_WF_A:
			size1 = size2 = 4;
			break;
		case DNSLIB_RDATA_WF_AAAA:
			size1 = size2 = 16;
			break;
		case DNSLIB_RDATA_WF_TEXT:
		case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
			size1 = (int)item1->raw_data[0] + 1;
			size2 = (int)item1->raw_data[0] + 1;
			break;
		case DNSLIB_RDATA_WF_BINARY:
		case DNSLIB_RDATA_WF_APL:            // saved as binary
		case DNSLIB_RDATA_WF_IPSECGATEWAY:   // saved as binary
			size1 = -1;
			size2 = -1;
			break;
		default:
			assert(0);
		}

		cmp = dnslib_rdata_compare_binary(data1, data2, size1, size2);

		if (cmp != 0) {
			return cmp;
		}
	}

	assert(cmp == 0);
	return 0;
}
