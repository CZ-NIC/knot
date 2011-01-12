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

#if defined(DNSLIB_ZONE_DEBUG) || defined(DNSLIB_RDATA_DEBUG)
void dnslib_rdata_dump(dnslib_rdata_t *rdata, uint32_t type);
#else
inline void dnslib_rdata_dump(dnslib_rdata_t *rdata, uint32_t type) {};
#endif

#if defined(DNSLIB_ZONE_DEBUG) || defined(DNSLIB_RRSET_DEBUG)
void dnslib_rrset_dump(dnslib_rrset_t *rrset);
#else
inline void dnslib_rrset_dump(dnslib_rrset_t *rrset) {};
#endif

#if defined(DNSLIB_ZONE_DEBUG) || defined(DNSLIB_NODE_DEBUG)
void dnslib_node_dump(dnslib_node_t *node, void *void_param);
#else
inline void dnslib_node_dump(dnslib_node_t *node, void *void_param) {};
#endif

#if defined(DNSLIB_ZONE_DEBUG)
void dnslib_zone_dump(dnslib_zone_t *zone);
#else
inline void dnslib_zone_dump(dnslib_zone_t *zone) {};
#endif

#endif

/*! @} */
