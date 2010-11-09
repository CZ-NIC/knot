#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "common.h"
#include "rdata.h"

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_rdata_t *dnslib_rdata_new( uint count )
{
	dnslib_rdata_t *rdata = (dnslib_rdata_t *)malloc(sizeof(dnslib_rdata_t));
	if (rdata == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	rdata->items = NULL;

	if (count > 0 (rdata->items = (dnslib_rdata_item_t *)calloc(
			count * sizeof(dnslib_rdata_item_t)) == NULL)) {
		ERR_ALLOC_FAILED;
		free(rdata);
		return NULL;
	}

	rdata->count = count;

	return rdata;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_set_item( dnslib_rdata *rdata, uint pos,
						   dnslib_rdata_item_t item )
{
	if (pos >= rdata->count) {
		return -1;
	}
	rdata->items[pos] = item;	// this should copy the union; or use memcpy?
	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_rdata_set_items( dnslib_rdata *rdata,
							const dnslib_rdata_item_t *items, uint count )
{
	if (count == 0) {
		return 1;
	}

	if (rdata->count == 0) {	// empty so far, allocate new space
		assert(rdata->items == NULL);
		if ((rdata->items = (dnslib_rdata_item_t *)malloc(
				count * sizeof(dnslib_rdata_item_t)) == NULL)) {
			ERR_ALLOC_FAILED;
			return -1;
		}
	} else if (rdata->count != count) {
		return -2;
	}

	memcpy(rdata->items, items, count * sizeof(dnslib_rdata_item_t));
	rdata->count = count;

	return 0;
}

/*----------------------------------------------------------------------------*/

const dnslib_rdata_item_t *dnslib_rdata_get_item( dnslib_rdata_t *rdata,
												  uint pos )
{
	if (pos >= rdata->count) {
		return NULL;
	}
	else return &rdata->items[pos];
}

/*----------------------------------------------------------------------------*/

void dnslib_rdata_free( dnslib_rdata_t *rdata )
{
	free(rdata->items);
	free(rdata);
}
