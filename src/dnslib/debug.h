/*
 * File:     debug.h
 * Date:     02.12.2010 13:45
 * Author:   jan
 * Project:  
 * Description:   
 */


#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdint.h>
#include "dnslib/dnslib.h"

void dnslib_rdata_dump(dnslib_rdata_t *rdata, uint32_t type);
void dnslib_rrset_dump(dnslib_rrset_t *rrset);
void dnslib_node_dump(dnslib_node_t *node, void *void_param);
void dnslib_zone_dump(dnslib_zone_t *zone);

#endif

/* end of file debug.h */
