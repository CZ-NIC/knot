/*
 * File:     rrset.c
 * Date:     11.11.2010 10:19
 * Author:   jan
 * Project:  
 * Description:   
 */

#include <stdint.h>
#include <malloc.h>

#include "rrset.h"
#include "common.h"

dnslib_rrset_t *dnslib_rrset_new( dnslib_dname_t *owner, uint16_t type,
                      uint16_t rclass, uint32_t ttl )
{
    dnslib_rrset_t *ret = malloc(sizeof(dnslib_rrset_t));
    if (ret == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }
    
    if ((ret->owner = dnslib_dname_new()) == NULL) {
        //Free ret here?
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

int dnslib_rrset_add_rdata( dnslib_rrset_t *rrset, dnslib_rdata_t *rdata )
/* TODO only stores at the beginning of the list */
{
    if (rrset->rdata == NULL) {
        if ((rrset->rdata = dnslib_rdata_new(1)) == NULL) {
            ERR_ALLOC_FAILED;
            return -1;
        }

        rrset->rdata->items = rdata->items;
        rrset->rdata->count = rdata->count;
        rrset->rdata->next = rrset->rdata;

    } else {
        dnslib_rdata_t *new_element = dnslib_rdata_new(1);
        if (new_element == NULL) {
            ERR_ALLOC_FAILED;
            return -1;
        }
        
        new_element->items = rdata->items;
        new_element->count = rdata->count;
        new_element->next = rrset->rdata;

        dnslib_rdata_t *tmp;

        tmp = rrset->rdata;

        /* find the last element in the list */
        while (tmp->next != rrset->rdata) { 
            tmp = tmp->next;
        }

        tmp->next = new_element; /* the last element now points to the first */
        rrset->rdata = new_element;
    }
    return 0;
}

int dnslib_rrset_set_rrsigs( dnslib_rrset_t *rrset,
							 const dnslib_rrset_t *rrsigs,
							 const dnslib_rdata_t *first, uint count )
{
    rrset->rrsigs = rrsigs;
    rrset->first = first;
    rrset->rrsig_count = count;
    /* TODO change to void in header */
}

uint16_t dnslib_rrset_type( const dnslib_rrset_t *rrset )
{
    return rrset->type;
}

uint16_t dnslib_rrset_class( const dnslib_rrset_t *rrset )
{
    return rrset->rclass;
}

uint32_t dnslib_rrset_ttl( const dnslib_rrset_t *rrset )
{
    return rrset->ttl;
}

const dnslib_rdata_t *dnslib_rrset_rdata( const dnslib_rrset_t *rrset )
{
    return rrset->rdata;
}

const dnslib_rrset_t *dnslib_rrset_rrsigs( const dnslib_rrset_t *rrset )
{
    return rrset->rrsigs;
}

const dnslib_rdata_t *dnslib_rrset_rrsig_first( const dnslib_rrset_t *rrset )
{
    return rrset->first;
}

uint dnslib_rrset_rrsig_count( const dnslib_rrset_t *rrset )
{
    return rrset->rrsig_count;
}

void dnslib_rrset_free( dnslib_rrset_t **rrset )
{
    *rrset = NULL;
}
/* end of file rrset.c */
