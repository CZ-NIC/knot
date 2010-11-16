#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "common.h"
#include "rdata.h"
#include "descriptor.h"
#include "dname.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static int dnslib_rdata_compare_binary( const uint8_t *d1, const uint8_t *d2,
										int count1, int count2 )
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
	dnslib_rdata_t *rdata = (dnslib_rdata_t *)malloc(sizeof(dnslib_rdata_t));
	if (rdata == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	rdata->items = NULL;
	rdata->count = 0;

	return rdata;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_set_item( dnslib_rdata_t *rdata, uint pos,
						   dnslib_rdata_item_t item )
{
	if (pos >= rdata->count) {
		return -1;
	}
	rdata->items[pos] = item;	// this should copy the union; or use memcpy?
	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_set_items( dnslib_rdata_t *rdata,
							const dnslib_rdata_item_t *items, uint count )
{
	if (count == 0) {
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

const dnslib_rdata_item_t *dnslib_rdata_get_item( const dnslib_rdata_t *rdata,
												  uint pos )
{
	if (pos >= rdata->count) {
		return NULL;
	}
	else return &rdata->items[pos];
}

/*----------------------------------------------------------------------------*/

void dnslib_rdata_free( dnslib_rdata_t **rdata )
{
	if (rdata == NULL || *rdata == NULL) {
		return;
	}

	free((*rdata)->items);
	free(*rdata);
	*rdata = NULL;
}

/*----------------------------------------------------------------------------*/

uint dnslib_rdata_wire_size( const dnslib_rdata_t *rdata,
							 const uint8_t *format )
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
		case DNSLIB_RDATA_WF_TEXT:
		case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
			// size stored in the first byte, but the first byte also counts
			size += rdata->items[i].raw_data[0] + 1;
			break;
		case DNSLIB_RDATA_WF_BINARY:
		case DNSLIB_RDATA_WF_APL:			// saved as binary
		case DNSLIB_RDATA_WF_IPSECGATEWAY:	// saved as binary
			// size stored in the first byte, first byte doesn't count
			size += rdata->items[i].raw_data[0];
			break;
		default:
			assert(0);
		}
	}
	return size;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_to_wire( const dnslib_rdata_t *rdata, const uint8_t *format,
						  uint8_t *buffer, uint buf_size )
{
	uint copied = 0;
	uint8_t tmp[MAX_RDATA_WIRE_SIZE];
	uint8_t *to = tmp;

	for (int i = 0; i < rdata->count; ++i) {
		assert(copied < MAX_RDATA_WIRE_SIZE);

		switch (format[i]) {
		case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_LITERAL_DNAME: {
			uint size = dnslib_dname_size(rdata->items[i].dname);
			memcpy(to, dnslib_dname_name(rdata->items[i].dname), size);
			to += size;
			copied += size;
		} break;
		case DNSLIB_RDATA_WF_BYTE:
			*(to++) = rdata->items[i].int8;
			++copied;
			break;
		case DNSLIB_RDATA_WF_SHORT: {
			const uint8_t *from = (uint8_t *)(&rdata->items[i].int16);
			// copy from last byte to first (little to big endian)
			// TODO: check endianness of the machine
			from += 1;
			for (int i = 0; i < 2; ++i) {
				*(to++) = *(from--);
				++copied;
			}
		} break;
		case DNSLIB_RDATA_WF_LONG: {
			const uint8_t *from = (uint8_t *)(&rdata->items[i].int32);
			// copy from last byte to first (little to big endian)
			// TODO: check endianness of the machine
			from += 3;
			for (int i = 0; i < 4; ++i) {
				*(to++) = *(from--);
				++copied;
			}
		} break;
		case DNSLIB_RDATA_WF_A: {
			const uint8_t *from = rdata->items[i].a;
			for (int i = 0; i < 4; ++i) {
				*(to++) = *(from++);
				++copied;
			}
		} break;
		case DNSLIB_RDATA_WF_AAAA: {
			const uint8_t *from = rdata->items[i].raw_data;
			for (int i = 0; i < 16; ++i) {
				*(to++) = *(from++);
				++copied;
			}
		} break;
		case DNSLIB_RDATA_WF_TEXT:
		case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
			// size stored in the first byte, but the first byte also needs to
			// be copied
			memcpy(to, rdata->items[i].raw_data,
				   rdata->items[i].raw_data[0] + 1);
			copied += rdata->items[i].raw_data[0] + 1;
			to += rdata->items[i].raw_data[0] + 1;
			break;
		case DNSLIB_RDATA_WF_BINARY:
		case DNSLIB_RDATA_WF_APL:			// saved as binary
		case DNSLIB_RDATA_WF_IPSECGATEWAY:	// saved as binary
			// size stored in the first byte, first byte must not be copied
			memcpy(to, &(rdata->items[i].raw_data[1]),
				   rdata->items[i].raw_data[0]);
			copied += rdata->items[i].raw_data[0];
			to += rdata->items[i].raw_data[0];
			break;
		default:
			assert(0);
		}
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

int dnslib_rdata_compare( const dnslib_rdata_t *r1, const dnslib_rdata_t *r2,
						  const uint8_t *format )
{
	uint count = (r1->count < r2->count) ? r1->count : r2->count;

	int cmp = 0;

	for (int i = 0; i < count; ++i) {
		dnslib_rdata_item_t *item1 = &r2->items[i];
		dnslib_rdata_item_t *item2 = &r2->items[i];

		switch (format[i]) {
		case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_LITERAL_DNAME:
			// maybe also compare with dnslib_rdata_compare_binary()
			cmp = dnslib_dname_compare(item1->dname, item2->dname);
			break;
		case DNSLIB_RDATA_WF_BYTE:
			cmp = (item1->int8 == item2->int8) ? 0 : (
					(r1->items[i].int8 < item2->int8) ? -1 : 1);
			break;
		case DNSLIB_RDATA_WF_SHORT:
			cmp = (item1->int16 == item2->int16) ? 0 : (
					(item1->int16 < item2->int16) ? -1 : 1);
			break;
		case DNSLIB_RDATA_WF_LONG:
			cmp = (item1->int32 == item2->int32) ? 0 : (
					(item1->int32 < item2->int32) ? -1 : 1);
			break;
		case DNSLIB_RDATA_WF_A:
			cmp = dnslib_rdata_compare_binary(item1->a, item2->a, 4, 4);
			break;
		case DNSLIB_RDATA_WF_AAAA:
			cmp = dnslib_rdata_compare_binary(item1->raw_data, item2->raw_data,
											  16, 16);
			break;
		case DNSLIB_RDATA_WF_TEXT:
		case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
			cmp = dnslib_rdata_compare_binary(&item1->raw_data[1],
					&item2->raw_data[1], (int)item1->raw_data[0],
					(int)item2->raw_data[0]);
			break;
		case DNSLIB_RDATA_WF_BINARY:
		case DNSLIB_RDATA_WF_APL:			// saved as binary
		case DNSLIB_RDATA_WF_IPSECGATEWAY:	// saved as binary
			cmp = dnslib_rdata_compare_binary(item1->a, item2->a, -1, -1);
			break;
		default:
			assert(0);
		}

		if (cmp != 0) {
			return cmp;
		}
	}

	assert(cmp == 0);
	return 0;
}
