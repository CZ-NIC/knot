#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "common.h"
#include "rdata.h"
#include "descriptor.h"
#include "dname.h"

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
