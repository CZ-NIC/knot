/*!
 * \file debug.h
 *
 * \author Jan Kadlec <jan.kadlec.@nic.cz>
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Functions for debug output of structures.
 *
 * \addtogroup libknot
 * @{
 */
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

#ifndef _KNOT_DEBUG_H_
#define _KNOT_DEBUG_H_

#include <stdint.h>
#include <stdio.h>
#include "rdata.h"
#include "rrset.h"
#include "zone/node.h"
#include "zone/zone.h"
#include "util/utils.h"
#include "common/print.h"

/*!
 * \brief Dumps RDATA of the given type.
 *
 * This function is empty if neither KNOT_ZONE_DEBUG nor KNOT_RDATA_DEBUG
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
 * This function is empty if neither KNOT_ZONE_DEBUG nor KNOT_RRSET_DEBUG
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
 * This function is empty if neither KNOT_ZONE_DEBUG nor KNOT_NODE_DEBUG
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
 * This function is empty if KNOT_ZONE_DEBUG is not defined.
 *
 * \param zone Zone to dump.
 * \param loaded_zone Set to <> 0 if the node is part of a zone loaded into
 *                    the server. Set to 0 otherwise.
 */
void knot_zone_contents_dump(knot_zone_contents_t *zone, char loaded_zone);

/*
 * Debug macros
 */
#define KNOT_ZONE_DEBUG
//#define KNOT_RESPONSE_DEBUG
//#define KNOT_ZONEDB_DEBUG
//#define KNOT_DNAME_DEBUG
//#define KNOT_NODE_DEBUG
//#define KNOT_RESPONSE_DEBUG
//#define KNOT_PACKET_DEBUG
//#define KNOT_EDNS_DEBUG
//#define KNOT_RRSET_DEBUG
//#define KNOT_NSEC3_DEBUG
//#define KNOT_ZDUMP_DEBUG
//#define KNOT_ZLOAD_DEBUG
//#define CUCKOO_DEBUG
//#define CUCKOO_DEBUG_HASH
//#define KNOT_NS_DEBUG
#define KNOT_XFR_DEBUG
//#define KNOT_DDNS_DEBUG

#ifdef KNOT_NS_DEBUG
#define debug_knot_ns(msg...) fprintf(stderr, msg)
#define debug_knot_ns_hex(data, len) hex_print((data), (len))
#define DEBUG_KNOT_NS(cmds) do { cmds } while (0)
#else
#define debug_knot_ns(msg...)
#define debug_knot_ns_hex(data, len)
#define DEBUG_KNOT_NS(cmds)
#endif

#ifdef KNOT_DNAME_DEBUG
#define debug_knot_dname(msg...) fprintf(stderr, msg)
#define debug_knot_dname_hex(data, len) hex_print((data), (len))
#define DEBUG_KNOT_DNAME(cmds) do { cmds } while (0)
#else
#define debug_knot_dname(msg...)
#define debug_knot_dname_hex(data, len)
#define DEBUG_KNOT_DNAME(cmds)
#endif

#ifdef KNOT_NODE_DEBUG
#define debug_knot_node(msg...) fprintf(stderr, msg)
#define debug_knot_node_hex(data, len) hex_print((data), (len))
#define DEBUG_KNOT_node(cmds) do { cmds } while (0)
#else
#define debug_knot_node(msg...)
#define debug_knot_node_hex(data, len)
#define DEBUG_KNOT_NODE(cmds)
#endif

#ifdef KNOT_ZONE_DEBUG
#define debug_knot_zone(msg...) fprintf(stderr, msg)
#define debug_knot_zone_hex(data, len) hex_print((data), (len))
#define DEBUG_KNOT_ZONE(cmds) do { cmds } while (0)
#else
#define debug_knot_zone(msg...)
#define debug_knot_zone_hex(data, len)
#define DEBUG_KNOT_ZONE(cmds)
#endif

#ifdef KNOT_ZONEDB_DEBUG
#define debug_knot_zonedb(msg...) fprintf(stderr, msg)
#define DEBUG_KNOT_ZONEDB(cmds) do { cmds } while (0)
#else
#define debug_knot_zonedb(msg...)
#define DEBUG_KNOT_ZONEDB(cmds)
#endif

#ifdef KNOT_RESPONSE_DEBUG
#define debug_knot_response(msg...) fprintf(stderr, msg)
#define debug_knot_response_hex(data, len) hex_print((data), (len))
#define DEBUG_KNOT_RESPONSE(cmds) do { cmds } while (0)
#else
#define debug_knot_response(msg...)
#define debug_knot_response_hex(data, len)
#define DEBUG_KNOT_RESPONSE(cmds)
#endif

#ifdef KNOT_PACKET_DEBUG
#define debug_knot_packet(msg...) fprintf(stderr, msg)
#define debug_knot_packet_hex(data, len) hex_print((data), (len))
#define DEBUG_KNOT_PACKET(cmds) do { cmds } while (0)
#else
#define debug_knot_packet(msg...)
#define debug_knot_packet_hex(data, len)
#define DEBUG_KNOT_PACKET(cmds)
#endif

#ifdef KNOT_EDNS_DEBUG
#define debug_knot_edns(msg...) fprintf(stderr, msg)
#else
#define debug_knot_edns(msg...)
#endif

#ifdef KNOT_NSEC3_DEBUG
#define debug_knot_nsec3(msg...) fprintf(stderr, msg)
#define debug_knot_nsec3_hex(data, len) hex_print((data), (len))
#define DEBUG_KNOT_NSEC3(cmds) do { cmds } while (0)
#else
#define debug_knot_nsec3(msg...)
#define debug_knot_nsec3_hex(data, len)
#define DEBUG_KNOT_NSEC3(cmds)
#endif

#ifdef KNOT_ZDUMP_DEBUG
#define debug_knot_zdump(msg...) fprintf(stderr, msg)
#define DEBUG_KNOT_ZDUMP(cmds) do { cmds } while (0)
#else
#define debug_knot_zdump(msg...)
#define DEBUG_KNOT_ZDUMP(cmds)
#endif

#ifdef KNOT_ZLOAD_DEBUG
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

#ifdef KNOT_XFR_DEBUG
#define debug_knot_xfr(msg...) fprintf(stderr, msg)
#define debug_knot_xfr_hex(data, len) hex_print((data), (len))
#define DEBUG_KNOT_XFR(cmds) do { cmds } while (0)
#else
#define debug_knot_xfr(msg...)
#define debug_knot_xfr_hex(data, len)
#define DEBUG_KNOT_XFR(cmds)
#endif

#ifdef KNOT_DDNS_DEBUG
#define debug_knot_ddns(msg...) fprintf(stderr, msg)
#define debug_knot_ddns_hex(data, len) hex_print((data), (len))
#define DEBUG_KNOT_DDNS(cmds) do { cmds } while (0)
#else
#define debug_knot_ddns(msg...)
#define debug_knot_ddns_hex(data, len)
#define DEBUG_KNOT_DDNS(cmds)
#endif

#endif

/*! @} */
