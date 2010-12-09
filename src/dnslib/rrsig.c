#include <stdlib.h>

#include "rrsig.h"
#include "common.h"

/*----------------------------------------------------------------------------*/

dnslib_rrsig_set_t *dnslib_rrsig_set_new(dnslib_dname_t *owner, uint16_t type,
                                         uint16_t rclass, uint32_t ttl)
{
	dnslib_rrsig_set_t *ret = malloc(sizeof(dnslib_rrsig_set_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ret->rdata = NULL;

	ret->owner = owner;
	ret->type = type;
	ret->rclass = rclass;
	ret->ttl = ttl;

	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_rrsig_set_add_rdata(dnslib_rrsig_set_t *rrsigs,
                               dnslib_rdata_t *rdata)
{
	if (rrsigs == NULL || rdata == NULL) {
		return -1;
	}

	if (rrsigs->rdata == NULL) {
		rrsigs->rdata = rdata;
		rrsigs->rdata->next = rrsigs->rdata;
	} else {
		dnslib_rdata_t *tmp;

		tmp = rrsigs->rdata;

		while (tmp->next != rrsigs->rdata) {
			tmp = tmp->next;
		}
		rdata->next = tmp->next;
		tmp->next = rdata;
	}
	return 0;
}

/*----------------------------------------------------------------------------*/

uint16_t dnslib_rrsig_set_type(const dnslib_rrsig_set_t *rrsigs)
{
	return rrsigs->type;
}

/*----------------------------------------------------------------------------*/

uint16_t dnslib_rrsig_set_class(const dnslib_rrsig_set_t *rrsigs)
{
	return rrsigs->rclass;
}

/*----------------------------------------------------------------------------*/

uint32_t dnslib_rrsig_set_ttl(const dnslib_rrsig_set_t *rrsigs)
{
	return rrsigs->ttl;
}

/*----------------------------------------------------------------------------*/

const dnslib_rdata_t *dnslib_rrsig_set_rdata(const dnslib_rrsig_set_t *rrsigs)
{
	return rrsigs->rdata;
}

/*----------------------------------------------------------------------------*/

void dnslib_rrsig_set_free(dnslib_rrsig_set_t **rrsigs)
{
	free(*rrsigs);
	*rrsigs = NULL;
}
