/*
 * File:     zone-load.h
 * Date:     15.12.2010 09:28
 * Author:   jan
 * Project:  
 * Description:   
 */


#ifndef __ZONELOAD_H__
#define __ZONELOAD_H__

#include "dnslib/zone.h"

dnslib_zone_t *dnslib_load_zone(const char *filename);

#endif

/* end of file zone-load.h */
