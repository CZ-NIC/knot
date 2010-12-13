#include <stdint.h>
#include <malloc.h>
#include <assert.h>

#include "rrset.h"
#include "descriptor.h"
#include "common.h"

dnslib_rrset_t *dnslib_rrset_new(dnslib_dname_t *owner, uint16_t type, 
				 uint16_t rclass, uint32_t ttl)
{
	dnslib_rrset_t *ret = malloc(sizeof(dnslib_rrset_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ret->rdata = NULL;

	ret->owner = owner;
	ret->type = type;
	ret->rclass = rclass;
	ret->ttl = ttl;
	ret->rrsigs = NULL;

	return ret;
}

int dnslib_rrset_add_rdata(dnslib_rrset_t *rrset, dnslib_rdata_t *rdata)
// TODO what if rdata is also cyclic linked list?
{
	if (rrset == NULL || rdata == NULL) {
		return -2;
	}

	if (rrset->rdata == NULL) {
		rrset->rdata = rdata;
		rrset->rdata->next = rrset->rdata;
	} else {
		dnslib_rdata_t *tmp;

		tmp = rrset->rdata;

		while (tmp->next != rrset->rdata) {
			tmp = tmp->next;
		}
		rdata->next = tmp->next;
		tmp->next = rdata;
	}
	return 0;
}

int dnslib_rrset_set_rrsigs(dnslib_rrset_t *rrset, dnslib_rrsig_set_t *rrsigs)
{
	if (rrset == NULL || rrsigs == NULL) {
		return -1;
	}

	rrset->rrsigs = rrsigs;
	return 0;
}

uint16_t dnslib_rrset_type(const dnslib_rrset_t *rrset)
{
	return rrset->type;
}

uint16_t dnslib_rrset_class(const dnslib_rrset_t *rrset)
{
	return rrset->rclass;
}

uint32_t dnslib_rrset_ttl(const dnslib_rrset_t *rrset)
{
	return rrset->ttl;
}

const dnslib_rdata_t *dnslib_rrset_rdata(const dnslib_rrset_t *rrset)
{
	return rrset->rdata;
}

const dnslib_rrsig_set_t *dnslib_rrset_rrsigs(const dnslib_rrset_t *rrset)
{
	return rrset->rrsigs;
}

void dnslib_rrset_free(dnslib_rrset_t **rrset)
{
	free(*rrset);
	*rrset = NULL;
}

int dnslib_rrset_merge(void **r1, void **r2)
{
	dnslib_rrset_t *rrset1 = (dnslib_rrset_t *)(*r1);
	dnslib_rrset_t *rrset2 = (dnslib_rrset_t *)(*r2);

	if (rrset1->owner != rrset2->owner
	    || rrset1->rclass != rrset2->rclass
	    || rrset1->type != rrset2->type
	    || rrset1->ttl != rrset2->ttl) {
		return -1;
	}

	// add all RDATAs from rrset2 to rrset1 (i.e. concatenate linked lists)

	// no RDATA in RRSet 1
	if (rrset1->rdata == NULL) {
		rrset1->rdata = rrset2->rdata;
		return 0;
	}

	dnslib_rdata_t *tmp_rdata = rrset1->rdata;

	while (tmp_rdata->next != rrset1->rdata) {
		tmp_rdata = tmp_rdata->next;
	}

	tmp_rdata->next = rrset2->rdata;

	tmp_rdata = rrset2->rdata; //maybe unnecessary, but is clearer

	while (tmp_rdata->next != rrset2->rdata) {
		tmp_rdata = tmp_rdata->next;
	}

	tmp_rdata->next = rrset1->rdata;

	return 0;
}
