#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/rrset.h"
#include "dnslib/descriptor.h"
#include "dnslib/error.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static void dnslib_rrset_disconnect_rdata(dnslib_rrset_t *rrset,
                                    dnslib_rdata_t *prev, dnslib_rdata_t *rdata)
{
	if (prev == NULL) {
		// find the previous RDATA in the series, as its pointer must
		// be changed
		dnslib_rdata_t *prev = rdata->next;
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

/*----------------------------------------------------------------------------*/

int dnslib_rrset_add_rdata(dnslib_rrset_t *rrset, dnslib_rdata_t *rdata)
{
	if (rrset == NULL || rdata == NULL) {
		return DNSLIB_EBADARG;
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
	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

dnslib_rdata_t *dnslib_rrset_remove_rdata(dnslib_rrset_t *rrset,
                                          const dnslib_rdata_t *rdata)
{
	if (rrset == NULL || rdata == NULL) {
		return NULL;
	}

	dnslib_rdata_t *prev = NULL;
	dnslib_rdata_t *rr = rrset->rdata;
	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(rrset->type);

	if (desc == NULL) {
		return NULL;
	}

	while (rr != NULL) {
		/*! \todo maybe the dnames should be compared case-insensitive*/
		if (dnslib_rdata_compare(rr, rdata, desc->wireformat) == 0) {
			dnslib_rrset_disconnect_rdata(rrset, prev, rr);
			return rr;
		}
		prev = rr;
		rr = dnslib_rrset_rdata_get_next(rrset, rr);
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

int dnslib_rrset_set_rrsigs(dnslib_rrset_t *rrset, dnslib_rrset_t *rrsigs)
{
	if (rrset == NULL || rrsigs == NULL) {
		return DNSLIB_EBADARG;
	}

	rrset->rrsigs = rrsigs;
	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_rrset_add_rrsigs(dnslib_rrset_t *rrset, dnslib_rrset_t *rrsigs,
                            dnslib_rrset_dupl_handling_t dupl)
{
	if (rrset == NULL || rrsigs == NULL
	    || dnslib_dname_compare(rrset->owner, rrsigs->owner) != 0) {
		return DNSLIB_EBADARG;
	}

	int rc;
	if (rrset->rrsigs != NULL) {
		if (dupl == DNSLIB_RRSET_DUPL_MERGE) {
			rc = dnslib_rrset_merge((void **)&rrset->rrsigs,
			                        (void **)&rrsigs);
			if (rc != DNSLIB_EOK) {
				return rc;
			} else {
				return 1;
			}
		} else if (dupl == DNSLIB_RRSET_DUPL_SKIP) {
			return 2;
		} else if (dupl == DNSLIB_RRSET_DUPL_REPLACE) {
			rrset->rrsigs = rrsigs;
		}
	} else {
		rrset->rrsigs = rrsigs;
	}

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

const dnslib_dname_t *dnslib_rrset_owner(const dnslib_rrset_t *rrset)
{
	return rrset->owner;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_rrset_get_owner(const dnslib_rrset_t *rrset)
{
	return rrset->owner;
}

/*----------------------------------------------------------------------------*/

uint16_t dnslib_rrset_type(const dnslib_rrset_t *rrset)
{
	return rrset->type;
}

/*----------------------------------------------------------------------------*/

uint16_t dnslib_rrset_class(const dnslib_rrset_t *rrset)
{
	return rrset->rclass;
}

/*----------------------------------------------------------------------------*/

uint32_t dnslib_rrset_ttl(const dnslib_rrset_t *rrset)
{
	return rrset->ttl;
}

/*----------------------------------------------------------------------------*/

const dnslib_rdata_t *dnslib_rrset_rdata(const dnslib_rrset_t *rrset)
{
	return rrset->rdata;
}

/*----------------------------------------------------------------------------*/

const dnslib_rdata_t *dnslib_rrset_rdata_next(const dnslib_rrset_t *rrset,
                                              const dnslib_rdata_t *rdata)
{
	if (rdata->next == rrset->rdata) {
		return NULL;
	} else {
		return rdata->next;
	}
}

/*----------------------------------------------------------------------------*/

dnslib_rdata_t *dnslib_rrset_get_rdata(dnslib_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	} else {
		return rrset->rdata;
	}
}

/*----------------------------------------------------------------------------*/

dnslib_rdata_t *dnslib_rrset_rdata_get_next(dnslib_rrset_t *rrset,
                                            dnslib_rdata_t *rdata)
{
	if (rdata->next == rrset->rdata) {
		return NULL;
	} else {
		return rdata->next;
	}
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t *dnslib_rrset_rrsigs(const dnslib_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	} else {
		return rrset->rrsigs;
	}
}

/*----------------------------------------------------------------------------*/

dnslib_rrset_t *dnslib_rrset_get_rrsigs(dnslib_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	} else {
		return rrset->rrsigs;
	}
}

/*----------------------------------------------------------------------------*/

int dnslib_rrset_compare(const dnslib_rrset_t *r1,
                         const dnslib_rrset_t *r2,
                         dnslib_rrset_compare_type_t cmp)
{
	if (cmp == DNSLIB_RRSET_COMPARE_PTR) {
		return (r1 == r2);
	}

	int res = ((r1->rclass == r2->rclass)
	           && (r1->type == r2->type)
	           && dnslib_dname_compare(r1->owner, r2->owner) == 0);

	if (cmp == DNSLIB_RRSET_COMPARE_WHOLE && res) {
		dnslib_rrtype_descriptor_t *desc =
			dnslib_rrtype_descriptor_by_type(r1->type);

		if (desc == NULL) {
			return 0;
		}

		res = res && (dnslib_rdata_compare(r1->rdata, r2->rdata,
		                                  desc->wireformat) == 0);
	}

	return res;
}

/*----------------------------------------------------------------------------*/

int dnslib_rrset_copy(const dnslib_rrset_t *from, dnslib_rrset_t **to)
{
	/*! \todo Implement (shallow copy). */
	return DNSLIB_ERROR;
}

/*----------------------------------------------------------------------------*/

void dnslib_rrset_free(dnslib_rrset_t **rrset)
{
	if (rrset == NULL || *rrset == NULL) {
		return;
	}

	free(*rrset);
	*rrset = NULL;
}

/*----------------------------------------------------------------------------*/

void dnslib_rrset_deep_free(dnslib_rrset_t **rrset, int free_owner,
                            int free_rdata, int free_rdata_dnames)
{
	if (rrset == NULL || *rrset == NULL) {
		return;
	}

	if (free_rdata) {
		dnslib_rdata_t *tmp_rdata;
		dnslib_rdata_t *next_rdata;
		tmp_rdata = (*rrset)->rdata;

		while ((tmp_rdata != NULL)
		       && (tmp_rdata->next != (*rrset)->rdata)
		       && (tmp_rdata->next != NULL)) {
			next_rdata = tmp_rdata->next;
			dnslib_rdata_deep_free(&tmp_rdata, (*rrset)->type,
					       free_rdata_dnames);
			tmp_rdata = next_rdata;
		}

		dnslib_rdata_deep_free(&tmp_rdata, (*rrset)->type,
		                       free_rdata_dnames);
	}

	// RRSIGs should have the same owner as this RRSet, so do not delete it
	if ((*rrset)->rrsigs != NULL) {
		dnslib_rrset_deep_free(&(*rrset)->rrsigs, 0, 1,
		                       free_rdata_dnames);
	}

	if (free_owner) {
		dnslib_dname_free(&(*rrset)->owner);
	}

	free(*rrset);
	*rrset = NULL;
}

/*----------------------------------------------------------------------------*/

int dnslib_rrset_merge(void **r1, void **r2)
{
	dnslib_rrset_t *rrset1 = (dnslib_rrset_t *)(*r1);
	dnslib_rrset_t *rrset2 = (dnslib_rrset_t *)(*r2);

	if ((dnslib_dname_compare(rrset1->owner, rrset2->owner) != 0)
	    || rrset1->rclass != rrset2->rclass
	    || rrset1->type != rrset2->type
	    || rrset1->ttl != rrset2->ttl) {
		return DNSLIB_EBADARG;
	}

	// add all RDATAs from rrset2 to rrset1 (i.e. concatenate linked lists)

	// no RDATA in RRSet 1
	assert(rrset1 && rrset2);
	if (rrset1->rdata == NULL) {
		rrset1->rdata = rrset2->rdata;
		return DNSLIB_EOK;
	}

	dnslib_rdata_t *tmp_rdata = rrset1->rdata;

	if (!tmp_rdata) {
		return DNSLIB_EOK;
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

	return DNSLIB_EOK;
}
