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
#ifndef _KNOT_DNSLIB_DEBUG_H_
#define _KNOT_DNSLIB_DEBUG_H_

#include <stdint.h>
#include <stdio.h>
#include "dnslib/rdata.h"
#include "dnslib/rrset.h"
#include "dnslib/node.h"
#include "dnslib/zone.h"

void dnslib_rdata_dump(dnslib_rdata_t *rdata, uint32_t type, char loaded_zone);

void dnslib_rrset_dump(dnslib_rrset_t *rrset, char loaded_zone);

void dnslib_node_dump(dnslib_node_t *node, void *data);

void dnslib_zone_dump(dnslib_zone_t *zone, char loaded_zone);

/*
 * Debug macros
 */
#define DNSLIB_ZONE_DEBUG
#define DNSLIB_RESPONSE_DEBUG
#define DNSLIB_ZONEDB_DEBUG
#define DNSLIB_DNAME_DEBUG
#define DNSLIB_RESPONSE_DEBUG
#define DNSLIB_EDNS_DEBUG
#define DNSLIB_RRSET_DEBUG
#define DNSLIB_NSEC3_DEBUG

#ifdef DNSLIB_DNAME_DEBUG
#define debug_dnslib_dname(msg...) fprintf(stderr, msg)
#define debug_dnslib_dname_hex(data, len) dnslib_hex_print((data), (len))
#define DEBUG_DNSLIB_DNAME(cmds) do { cmds } while (0)
#else
#define debug_dnslib_dname(msg...)
#define debug_dnslib_dname_hex(data, len)
#define DEBUG_DNSLIB_DNAME(cmds)
#endif

#ifdef DNSLIB_ZONE_DEBUG
#define debug_dnslib_zone(msg...) fprintf(stderr, msg)
#define debug_dnslib_zone_hex(data, len) dnslib_hex_print((data), (len))
#define DEBUG_DNSLIB_ZONE(cmds) do { cmds } while (0)
#else
#define debug_dnslib_zone(msg...)
#define debug_dnslib_zone_hex(data, len)
#define DEBUG_DNSLIB_ZONE(cmds)
#endif

#ifdef DNSLIB_ZONEDB_DEBUG
#define debug_dnslib_zonedb(msg...) fprintf(stderr, msg)
#define DEBUG_DNSLIB_ZONEDB(cmds) do { cmds } while (0)
#else
#define debug_dnslib_zonedb(msg...)
#define DEBUG_DNSLIB_ZONEDB(cmds)
#endif

#ifdef DNSLIB_RESPONSE_DEBUG
#define debug_dnslib_response(msg...) fprintf(stderr, msg)
#define debug_dnslib_response_hex(data, len) dnslib_hex_print((data), (len))
#define DEBUG_DNSLIB_RESPONSE(cmds) do { cmds } while (0)
#else
#define debug_dnslib_response(msg...)
#define debug_dnslib_response_hex(data, len)
#define DEBUG_DNSLIB_RESPONSE(cmds)
#endif

#ifdef DNSLIB_EDNS_DEBUG
#define debug_dnslib_edns(msg...) fprintf(stderr, msg)
#else
#define debug_dnslib_edns(msg...)
#endif

#ifdef DNSLIB_NSEC3_DEBUG
#define debug_dnslib_nsec3(msg...) fprintf(stderr, msg)
#define debug_dnslib_nsec3_hex(data, len) dnslib_hex_print((data), (len))
#define DEBUG_DNSLIB_NSEC3(cmds) do { cmds } while (0)
#else
#define debug_dnslib_nsec3(msg...)
#define debug_dnslib_nsec3_hex(data, len)
#define DEBUG_DNSLIB_NSEC3(cmds)
#endif

#endif

/*! @} */
