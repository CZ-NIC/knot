/*!
 * \file descriptor.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Functions for debug output of dnslib structures.
 *
 * \addtogroup dnslib
 * @{
 */
#ifndef _CUTEDNS_DNSLIB_DEBUG_H_
#define _CUTEDNS_DNSLIB_DEBUG_H_

#include <stdint.h>
#include "dnslib.h"

void dnslib_rdata_dump(dnslib_rdata_t *rdata, uint32_t type);

void dnslib_rrset_dump(dnslib_rrset_t *rrset);

void dnslib_node_dump(dnslib_node_t *node, void *void_param);

void dnslib_zone_dump(dnslib_zone_t *zone);

#endif

/*! @} */
