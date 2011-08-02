/*!
 * \file dnslib/debug.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 * \author Lubos Slovak <lubos.slovak@nic.cz>
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
#include "dnslib/utils.h"
#include "common/print.h"

/*!
 * \brief Dumps RDATA of the given type.
 *
 * This function is empty if neither DNSLIB_ZONE_DEBUG nor DNSLIB_RDATA_DEBUG
 * is defined.
 *
 * \param rdata RDATA to dump.
 * \param type Type of the RDATA (needed to properly parse the RDATA).
 * \param loaded_zone Set to <> 0 if the RDATA is part of a zone loaded into
 *                    the server. Set to 0 otherwise.
 */
void knot_rdata_dump(knot_rdata_t *rdata, uint32_t type, char loaded_zone);

/*!
 * \brief Dumps RRSet.
 *
 * This function is empty if neither DNSLIB_ZONE_DEBUG nor DNSLIB_RRSET_DEBUG
 * is defined.
 *
 * \param rrset RRSet to dump.
 * \param loaded_zone Set to <> 0 if the RRSet is part of a zone loaded into
 *                    the server. Set to 0 otherwise.
 */
void knot_rrset_dump(knot_rrset_t *rrset, char loaded_zone);

/*!
 * \brief Dumps zone node.
 *
 * This function is empty if neither DNSLIB_ZONE_DEBUG nor DNSLIB_NODE_DEBUG
 * is defined.
 *
 * \param node Node to dump.
 * \param loaded_zone Set to <> 0 if the node is part of a zone loaded into
 *                    the server. Set to 0 otherwise.
 */
void knot_node_dump(knot_node_t *node, void *loaded_zone);

/*!
 * \brief Dumps the whole zone.
 *
 * This function is empty if DNSLIB_ZONE_DEBUG is not defined.
 *
 * \param zone Zone to dump.
 * \param loaded_zone Set to <> 0 if the node is part of a zone loaded into
 *                    the server. Set to 0 otherwise.
 */
void knot_zone_contents_dump(knot_zone_contents_t *zone, char loaded_zone);

/*
 * Debug macros
 */
//#define DNSLIB_ZONE_DEBUG
//#define DNSLIB_RESPONSE_DEBUG
//#define DNSLIB_ZONEDB_DEBUG
//#define DNSLIB_DNAME_DEBUG
//#define DNSLIB_NODE_DEBUG
//#define DNSLIB_RESPONSE_DEBUG
//#define DNSLIB_PACKET_DEBUG
//#define DNSLIB_EDNS_DEBUG
//#define DNSLIB_RRSET_DEBUG
//#define DNSLIB_NSEC3_DEBUG
//#define DNSLIB_ZDUMP_DEBUG
//#define DNSLIB_ZLOAD_DEBUG
//#define CUCKOO_DEBUG
//#define CUCKOO_DEBUG_HASH
//#define DNSLIB_NS_DEBUG
//#define DNSLIB_XFR_DEBUG

#ifdef DNSLIB_XFR_DEBUG
#define debug_knot_xfr(msg...) fprintf(stderr, msg)
#define debug_knot_xfr_hex(data, len) hex_print((data), (len))
#define DEBUG_DNSLIB_NS(cmds) do { cmds } while (0)
#else
#define debug_knot_xfr(msg...)
#define debug_knot_xfr_hex(data, len)
#define DEBUG_DNSLIB_XFR(cmds)
#endif

#ifdef DNSLIB_NS_DEBUG
#define debug_knot_ns(msg...) fprintf(stderr, msg)
#define debug_knot_ns_hex(data, len) hex_print((data), (len))
#define DEBUG_DNSLIB_NS(cmds) do { cmds } while (0)
#else
#define debug_knot_ns(msg...)
#define debug_knot_ns_hex(data, len)
#define DEBUG_DNSLIB_NS(cmds)
#endif

#ifdef DNSLIB_DNAME_DEBUG
#define debug_knot_dname(msg...) fprintf(stderr, msg)
#define debug_knot_dname_hex(data, len) hex_print((data), (len))
#define DEBUG_DNSLIB_DNAME(cmds) do { cmds } while (0)
#else
#define debug_knot_dname(msg...)
#define debug_knot_dname_hex(data, len)
#define DEBUG_DNSLIB_DNAME(cmds)
#endif

#ifdef DNSLIB_NODE_DEBUG
#define debug_knot_node(msg...) fprintf(stderr, msg)
#define debug_knot_node_hex(data, len) hex_print((data), (len))
#define DEBUG_DNSLIB_node(cmds) do { cmds } while (0)
#else
#define debug_knot_node(msg...)
#define debug_knot_node_hex(data, len)
#define DEBUG_DNSLIB_NODE(cmds)
#endif

#ifdef DNSLIB_ZONE_DEBUG
#define debug_knot_zone(msg...) fprintf(stderr, msg)
#define debug_knot_zone_hex(data, len) hex_print((data), (len))
#define DEBUG_DNSLIB_ZONE(cmds) do { cmds } while (0)
#else
#define debug_knot_zone(msg...)
#define debug_knot_zone_hex(data, len)
#define DEBUG_DNSLIB_ZONE(cmds)
#endif

#ifdef DNSLIB_ZONEDB_DEBUG
#define debug_knot_zonedb(msg...) fprintf(stderr, msg)
#define DEBUG_DNSLIB_ZONEDB(cmds) do { cmds } while (0)
#else
#define debug_knot_zonedb(msg...)
#define DEBUG_DNSLIB_ZONEDB(cmds)
#endif

#ifdef DNSLIB_RESPONSE_DEBUG
#define debug_knot_response(msg...) fprintf(stderr, msg)
#define debug_knot_response_hex(data, len) hex_print((data), (len))
#define DEBUG_DNSLIB_RESPONSE(cmds) do { cmds } while (0)
#else
#define debug_knot_response(msg...)
#define debug_knot_response_hex(data, len)
#define DEBUG_DNSLIB_RESPONSE(cmds)
#endif

#ifdef DNSLIB_PACKET_DEBUG
#define debug_knot_packet(msg...) fprintf(stderr, msg)
#define debug_knot_packet_hex(data, len) hex_print((data), (len))
#define DEBUG_DNSLIB_PACKET(cmds) do { cmds } while (0)
#else
#define debug_knot_packet(msg...)
#define debug_knot_packet_hex(data, len)
#define DEBUG_DNSLIB_PACKET(cmds)
#endif

#ifdef DNSLIB_EDNS_DEBUG
#define debug_knot_edns(msg...) fprintf(stderr, msg)
#else
#define debug_knot_edns(msg...)
#endif

#ifdef DNSLIB_NSEC3_DEBUG
#define debug_knot_nsec3(msg...) fprintf(stderr, msg)
#define debug_knot_nsec3_hex(data, len) hex_print((data), (len))
#define DEBUG_DNSLIB_NSEC3(cmds) do { cmds } while (0)
#else
#define debug_knot_nsec3(msg...)
#define debug_knot_nsec3_hex(data, len)
#define DEBUG_DNSLIB_NSEC3(cmds)
#endif

#ifdef DNSLIB_ZDUMP_DEBUG
#define debug_knot_zdump(msg...) fprintf(stderr, msg)
#define DEBUG_DNSLIB_ZDUMP(cmds) do { cmds } while (0)
#else
#define debug_knot_zdump(msg...)
#define DEBUG_DNSLIB_ZDUMP(cmds)
#endif

#ifdef DNSLIB_ZLOAD_DEBUG
#define debug_knot_zload(msg...) fprintf(stderr, msg)
#else
#define debug_knot_zload(msg...)
#endif

#ifdef CUCKOO_DEBUG
#define debug_ck(msg...) fprintf(stderr, msg)
#else
#define debug_ck(msg...)
#endif

#ifdef CUCKOO_DEBUG_HASH
#define debug_ck_hash(msg...) fprintf(stderr, msg)
#define debug_ck_hash_hex(data, len) hex_print((data), (len))
#define debug_ck_rehash(msg...) fprintf(stderr, msg)
#else
#define debug_ck_hash(msg...)
#define debug_ck_hash_hex(data, len)
#define debug_ck_rehash(msg...)
#endif

#ifdef DNSLIB_XFR_DEBUG
#define debug_knot_xfr(msg...) fprintf(stderr, msg)
#define debug_knot_xfr_hex(data, len) hex_print((data), (len))
#define DEBUG_DNSLIB_XFR(cmds) do { cmds } while (0)
#else
#define debug_knot_xfr(msg...)
#define debug_knot_xfr_hex(data, len)
#define DEBUG_DNSLIB_XFR(cmds)
#endif

#endif

/*! @} */
