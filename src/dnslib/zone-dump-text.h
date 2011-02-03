/*
 * File:     zone-dump-text.h
 * Date:     03.02.2011 15:26
 * Author:   jan
 * Project:  
 * Description:   
 */

#ifndef __ZONE-DUMP-TEXT_H__
#define __ZONE-DUMP-TEXT_H__

#include "descriptor.h"
#include "rdata.h"

char *rdata_item_to_string(dnslib_rdata_zoneformat_t type, dnslib_rdata_item_t item);

#endif

/* end of file zone-dump-text.h */
