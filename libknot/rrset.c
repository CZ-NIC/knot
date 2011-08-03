/*  Copyright (C) 2011 CZ.NIC Labs

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
#include "descriptor.h"
#include "error.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static void knot_rrset_disconnect_rdata(knot_rrset_t *rrset,
                                    knot_rdata_t *prev, knot_rdata_t *rdata)
{
	if (prev == NULL) {
		// find the previous RDATA in the series, as its pointer must
		// be changed
		knot_rdata_t *prev = rdata->next;
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
	if (rrset == NULL || rrsigs == NULL) {
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

const knot_rrset_t *knot_rrset_rrsigs(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	} else {
		return rrset->rrsigs;
	}
}

/*----------------------------------------------------------------------------*/

knot_rrset_t *knot_rrset_get_rrsigs(knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	} else {
		return rrset->rrsigs;
	}
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
		knot_rrtype_descriptor_t *desc =
			knot_rrtype_descriptor_by_type(r1->type);

		if (desc == NULL) {
			return 0;
		}

		res = res && (knot_rdata_compare(r1->rdata, r2->rdata,
		                                  desc->wireformat) == 0);
	}

	return res;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_shallow_copy(const knot_rrset_t *from, knot_rrset_t **to)
{
	*to = (knot_rrset_t *)malloc(sizeof(knot_rrset_t));
	CHECK_ALLOC_LOG(*to, KNOT_ENOMEM);
	
	memcpy(*to, from, sizeof(knot_rrset_t));
	
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
