/*!
 * \file debug.h
 *
 * \author Jan Kadlec <jan.kadlec.@nic.cz>
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
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

#include "config.h" /* autoconf generated */

#include "rdata.h"
#include "rrset.h"
#include "zone/node.h"
#include "zone/zone.h"
#include "util/utils.h"
#include "common/print.h"

/*
 * Debug macros
 */
/*! \todo Set these during configure. */
//#define KNOT_ZONE_DEBUG
//#define KNOT_RESPONSE_DEBUG
//#define KNOT_ZONEDB_DEBUG
//#define KNOT_DNAME_DEBUG
//#define KNOT_NODE_DEBUG
//#define KNOT_PACKET_DEBUG
//#define KNOT_EDNS_DEBUG
//#define KNOT_RRSET_DEBUG
//#define KNOT_NSEC3_DEBUG
//#define CUCKOO_DEBUG
//#define CUCKOO_DEBUG_HASH
//#define KNOT_NS_DEBUG
//#define KNOT_XFR_DEBUG
//#define KNOT_DDNS_DEBUG

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
void knot_rrset_dump(const knot_rrset_t *rrset, char loaded_zone);

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

/******************************************************************************/

#ifdef KNOT_NS_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_knot_ns(msg...) fprintf(stderr, msg)
#define dbg_knot_ns_hex(data, len)  hex_print((data), (len))
#define dbg_knot_ns_exec(cmds) do { cmds } while (0)
#else
#define dbg_knot_ns(msg...)
#define dbg_knot_ns_hex(data, len)
#define dbg_knot_ns_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_knot_ns_verb(msg...) fprintf(stderr, msg)
#define dbg_knot_ns_hex_verb(data, len)  hex_print((data), (len))
#define dbg_knot_ns_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_knot_ns_verb(msg...)
#define dbg_knot_ns_hex_verb(data, len)
#define dbg_knot_ns_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_knot_ns_detail(msg...) fprintf(stderr, msg)
#define dbg_knot_ns_hex_detail(data, len)  hex_print((data), (len))
#define dbg_knot_ns_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_knot_ns_detail(msg...)
#define dbg_knot_ns_hex_detail(data, len)
#define dbg_knot_ns_exec_verb(cmds)
#endif

/* No messages. */
#else
#define dbg_knot_ns(msg...)
#define dbg_knot_ns_hex(data, len)
#define dbg_knot_ns_exec(cmds)
#define dbg_knot_ns_verb(msg...)
#define dbg_knot_ns_hex_verb(data, len)
#define dbg_knot_ns_exec_verb(cmds)
#define dbg_knot_ns_detail(msg...)
#define dbg_knot_ns_hex_detail(data, len)
#define dbg_knot_ns_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_DNAME_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_knot_dname(msg...) fprintf(stderr, msg)
#define dbg_knot_dname_hex(data, len)  hex_print((data), (len))
#define dbg_knot_dname_exec(cmds) do { cmds } while (0)
#else
#define dbg_knot_dname(msg...)
#define dbg_knot_dname_hex(data, len)
#define dbg_knot_dname_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_knot_dname_verb(msg...) fprintf(stderr, msg)
#define dbg_knot_dname_hex_verb(data, len)  hex_print((data), (len))
#define dbg_knot_dname_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_knot_dname_verb(msg...)
#define dbg_knot_dname_hex_verb(data, len)
#define dbg_knot_dname_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_knot_dname_detail(msg...) fprintf(stderr, msg)
#define dbg_knot_dname_hex_detail(data, len)  hex_print((data), (len))
#define dbg_knot_dname_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_knot_dname_detail(msg...)
#define dbg_knot_dname_hex_detail(data, len)
#define dbg_knot_dname_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_knot_dname(msg...)
#define dbg_knot_dname_hex(data, len)
#define dbg_knot_dname_exec(cmds)
#define dbg_knot_dname_verb(msg...)
#define dbg_knot_dname_hex_verb(data, len)
#define dbg_knot_dname_exec_verb(cmds)
#define dbg_knot_dname_detail(msg...)
#define dbg_knot_dname_hex_detail(data, len)
#define dbg_knot_dname_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_NODE_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_knot_node(msg...) fprintf(stderr, msg)
#define dbg_knot_node_hex(data, len)  hex_print((data), (len))
#else
#define dbg_knot_node(msg...)
#define dbg_knot_node_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_knot_node_verb(msg...) fprintf(stderr, msg)
#define dbg_knot_node_hex_verb(data, len)  hex_print((data), (len))
#else
#define dbg_knot_node_verb(msg...)
#define dbg_knot_node_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_knot_node_detail(msg...) fprintf(stderr, msg)
#define dbg_knot_node_hex_detail(data, len)  hex_print((data), (len))
#else
#define dbg_knot_node_detail(msg...)
#define dbg_knot_node_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_knot_node(msg...)
#define dbg_knot_node_hex(data, len)
#define dbg_knot_node_verb(msg...)
#define dbg_knot_node_hex_verb(data, len)
#define dbg_knot_node_detail(msg...)
#define dbg_knot_node_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOT_ZONE_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_knot_zone(msg...) fprintf(stderr, msg)
#define dbg_knot_zone_hex(data, len)  hex_print((data), (len))
#define dbg_knot_zone_exec(cmds) do { cmds } while (0)
#else
#define dbg_knot_zone(msg...)
#define dbg_knot_zone_hex(data, len)
#define dbg_knot_zone_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_knot_zone_verb(msg...) fprintf(stderr, msg)
#define dbg_knot_zone_hex_verb(data, len)  hex_print((data), (len))
#define dbg_knot_zone_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_knot_zone_verb(msg...)
#define dbg_knot_zone_hex_verb(data, len)
#define dbg_knot_zone_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_knot_zone_detail(msg...) fprintf(stderr, msg)
#define dbg_knot_zone_hex_detail(data, len)  hex_print((data), (len))
#define dbg_knot_zone_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_knot_zone_detail(msg...)
#define dbg_knot_zone_hex_detail(data, len)
#define dbg_knot_zone_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_knot_zone(msg...)
#define dbg_knot_zone_hex(data, len)
#define dbg_knot_zone_exec(cmds)
#define dbg_knot_zone_verb(msg...)
#define dbg_knot_zone_hex_verb(data, len)
#define dbg_knot_zone_exec_verb(cmds)
#define dbg_knot_zone_detail(msg...)
#define dbg_knot_zone_hex_detail(data, len)
#define dbg_knot_zone_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_ZONEDB_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_knot_zonedb(msg...) fprintf(stderr, msg)
#define dbg_knot_zonedb_hex(data, len)  hex_print((data), (len))
#define dbg_knot_zonedb_exec(cmds) do { cmds } while (0)
#else
#define dbg_knot_zonedb(msg...)
#define dbg_knot_zonedb_hex(data, len)
#define dbg_knot_zonedb_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_knot_zonedb_verb(msg...) fprintf(stderr, msg)
#define dbg_knot_zonedb_hex_verb(data, len)  hex_print((data), (len))
#define dbg_knot_zonedb_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_knot_zonedb_verb(msg...)
#define dbg_knot_zonedb_hex_verb(data, len)
#define dbg_knot_zonedb_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_knot_zonedb_detail(msg...) fprintf(stderr, msg)
#define dbg_knot_zonedb_hex_detail(data, len)  hex_print((data), (len))
#define dbg_knot_zonedb_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_knot_zonedb_detail(msg...)
#define dbg_knot_zonedb_hex_detail(data, len)
#define dbg_knot_zonedb_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_knot_zonedb(msg...)
#define dbg_knot_zonedb_hex(data, len)
#define dbg_knot_zonedb_exec(cmds)
#define dbg_knot_zonedb_verb(msg...)
#define dbg_knot_zonedb_hex_verb(data, len)
#define dbg_knot_zonedb_exec_verb(cmds)
#define dbg_knot_zonedb_detail(msg...)
#define dbg_knot_zonedb_hex_detail(data, len)
#define dbg_knot_zonedb_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_RESPONSE_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_knot_response(msg...) fprintf(stderr, msg)
#define dbg_knot_response_hex(data, len)  hex_print((data), (len))
#define dbg_knot_response_exec(cmds) do { cmds } while (0)
#else
#define dbg_knot_response(msg...)
#define dbg_knot_response_hex(data, len)
#define dbg_knot_response_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_knot_response_verb(msg...) fprintf(stderr, msg)
#define dbg_knot_response_hex_verb(data, len)  hex_print((data), (len))
#define dbg_knot_response_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_knot_response_verb(msg...)
#define dbg_knot_response_hex_verb(data, len)
#define dbg_knot_response_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_knot_response_detail(msg...) fprintf(stderr, msg)
#define dbg_knot_response_hex_detail(data, len)  hex_print((data), (len))
#define dbg_knot_response_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_knot_response_detail(msg...)
#define dbg_knot_response_hex_detail(data, len)
#define dbg_knot_response_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_knot_response(msg...)
#define dbg_knot_response_hex(data, len)
#define dbg_knot_response_exec(cmds)
#define dbg_knot_response_verb(msg...)
#define dbg_knot_response_hex_verb(data, len)
#define dbg_knot_response_exec_verb(cmds)
#define dbg_knot_response_detail(msg...)
#define dbg_knot_response_hex_detail(data, len)
#define dbg_knot_response_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_PACKET_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_knot_packet(msg...) fprintf(stderr, msg)
#define dbg_knot_packet_hex(data, len)  hex_print((data), (len))
#define dbg_knot_packet_exec(cmds) do { cmds } while (0)
#else
#define dbg_knot_packet(msg...)
#define dbg_knot_packet_hex(data, len)
#define dbg_knot_packet_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_knot_packet_verb(msg...) fprintf(stderr, msg)
#define dbg_knot_packet_hex_verb(data, len)  hex_print((data), (len))
#define dbg_knot_packet_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_knot_packet_verb(msg...)
#define dbg_knot_packet_hex_verb(data, len)
#define dbg_knot_packet_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_knot_packet_detail(msg...) fprintf(stderr, msg)
#define dbg_knot_packet_hex_detail(data, len)  hex_print((data), (len))
#define dbg_knot_packet_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_knot_packet_detail(msg...)
#define dbg_knot_packet_hex_detail(data, len)
#define dbg_knot_packet_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_knot_packet(msg...)
#define dbg_knot_packet_hex(data, len)
#define dbg_knot_packet_exec(cmds)
#define dbg_knot_packet_verb(msg...)
#define dbg_knot_packet_hex_verb(data, len)
#define dbg_knot_packet_exec_verb(cmds)
#define dbg_knot_packet_detail(msg...)
#define dbg_knot_packet_hex_detail(data, len)
#define dbg_knot_packet_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_EDNS_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_knot_edns(msg...) fprintf(stderr, msg)
#define dbg_knot_edns_hex(data, len)  hex_print((data), (len))
#else
#define dbg_knot_edns(msg...)
#define dbg_knot_edns_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_knot_edns_verb(msg...) fprintf(stderr, msg)
#define dbg_knot_edns_hex_verb(data, len)  hex_print((data), (len))
#else
#define dbg_knot_edns_verb(msg...)
#define dbg_knot_edns_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_knot_edns_detail(msg...) fprintf(stderr, msg)
#define dbg_knot_edns_hex_detail(data, len)  hex_print((data), (len))
#else
#define dbg_knot_edns_detail(msg...)
#define dbg_knot_edns_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_knot_edns(msg...)
#define dbg_knot_edns_hex(data, len)
#define dbg_knot_edns_verb(msg...)
#define dbg_knot_edns_hex_verb(data, len)
#define dbg_knot_edns_detail(msg...)
#define dbg_knot_edns_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOT_NSEC3_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_knot_nsec3(msg...) fprintf(stderr, msg)
#define dbg_knot_nsec3_hex(data, len)  hex_print((data), (len))
#else
#define dbg_knot_nsec3(msg...)
#define dbg_knot_nsec3_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_knot_nsec3_verb(msg...) fprintf(stderr, msg)
#define dbg_knot_nsec3_hex_verb(data, len)  hex_print((data), (len))
#else
#define dbg_knot_nsec3_verb(msg...)
#define dbg_knot_nsec3_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_knot_nsec3_detail(msg...) fprintf(stderr, msg)
#define dbg_knot_nsec3_hex_detail(data, len)  hex_print((data), (len))
#else
#define dbg_knot_nsec3_detail(msg...)
#define dbg_knot_nsec3_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_knot_nsec3(msg...)
#define dbg_knot_nsec3_hex(data, len)
#define dbg_knot_nsec3_verb(msg...)
#define dbg_knot_nsec3_hex_verb(data, len)
#define dbg_knot_nsec3_detail(msg...)
#define dbg_knot_nsec3_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef CUCKOO_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_ck(msg...) fprintf(stderr, msg)
#define dbg_ck_hex(data, len)  hex_print((data), (len))
#else
#define dbg_ck(msg...)
#define dbg_ck_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_ck_verb(msg...) fprintf(stderr, msg)
#define dbg_ck_hex_verb(data, len)  hex_print((data), (len))
#else
#define dbg_ck_verb(msg...)
#define dbg_ck_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_ck_detail(msg...) fprintf(stderr, msg)
#define dbg_ck_hex_detail(data, len)  hex_print((data), (len))
#else
#define dbg_ck_detail(msg...)
#define dbg_ck_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_ck(msg...)
#define dbg_ck_hex(data, len)
#define dbg_ck_verb(msg...)
#define dbg_ck_hex_verb(data, len)
#define dbg_ck_detail(msg...)
#define dbg_ck_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef CUCKOO_DEBUG_HASH

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_ck_hash(msg...) fprintf(stderr, msg)
#define dbg_ck_rehash(msg...) fprintf(stderr, msg)
#define dbg_ck_hash_hex(data, len)  hex_print((data), (len))
#else
#define dbg_ck_hash(msg...)
#define dbg_ck_rehash(msg...)
#define dbg_ck_hash_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_ck_hash_verb(msg...) fprintf(stderr, msg)
#define dbg_ck_hash_hex_verb(data, len)  hex_print((data), (len))
#else
#define dbg_ck_hash_verb(msg...)
#define dbg_ck_hash_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_ck_hash_detail(msg...) fprintf(stderr, msg)
#define dbg_ck_hash_hex_detail(data, len)  hex_print((data), (len))
#else
#define dbg_ck_hash_detail(msg...)
#define dbg_ck_hash_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_ck_hash(msg...)
#define dbg_ck_rehash(msg...)
#define dbg_ck_hash_hex(data, len)
#define dbg_ck_hash_verb(msg...)
#define dbg_ck_hash_hex_verb(data, len)
#define dbg_ck_hash_detail(msg...)
#define dbg_ck_hash_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOT_XFR_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_knot_xfr(msg...) fprintf(stderr, msg)
#define dbg_knot_xfr_hex(data, len)  hex_print((data), (len))
#define dbg_knot_xfr_exec(cmds) do { cmds } while (0)
#else
#define dbg_knot_xfr(msg...)
#define dbg_knot_xfr_hex(data, len)
#define dbg_knot_xfr_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_knot_xfr_verb(msg...) fprintf(stderr, msg)
#define dbg_knot_xfr_hex_verb(data, len)  hex_print((data), (len))
#define dbg_knot_xfr_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_knot_xfr_verb(msg...)
#define dbg_knot_xfr_hex_verb(data, len)
#define dbg_knot_xfr_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_knot_xfr_detail(msg...) fprintf(stderr, msg)
#define dbg_knot_xfr_hex_detail(data, len)  hex_print((data), (len))
#define dbg_knot_xfr_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_knot_xfr_detail(msg...)
#define dbg_knot_xfr_hex_detail(data, len)
#define dbg_knot_xfr_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_knot_xfr(msg...)
#define dbg_knot_xfr_hex(data, len)
#define dbg_knot_xfr_exec(cmds)
#define dbg_knot_xfr_verb(msg...)
#define dbg_knot_xfr_hex_verb(data, len)
#define dbg_knot_xfr_exec_verb(cmds)
#define dbg_knot_xfr_detail(msg...)
#define dbg_knot_xfr_hex_detail(data, len)
#define dbg_knot_xfr_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_DDNS_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_knot_ddns(msg...) fprintf(stderr, msg)
#define dbg_knot_ddns_hex(data, len)  hex_print((data), (len))
#else
#define dbg_knot_ddns(msg...)
#define dbg_knot_ddns_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_knot_ddns_verb(msg...) fprintf(stderr, msg)
#define dbg_knot_ddns_hex_verb(data, len)  hex_print((data), (len))
#else
#define dbg_knot_ddns_verb(msg...)
#define dbg_knot_ddns_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_knot_ddns_detail(msg...) fprintf(stderr, msg)
#define dbg_knot_ddns_hex_detail(data, len)  hex_print((data), (len))
#else
#define dbg_knot_ddns_detail(msg...)
#define dbg_knot_ddns_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_knot_ddns(msg...)
#define dbg_knot_ddns_hex(data, len)
#define dbg_knot_ddns_verb(msg...)
#define dbg_knot_ddns_hex_verb(data, len)
#define dbg_knot_ddns_detail(msg...)
#define dbg_knot_ddns_hex_detail(data, len)
#endif

/******************************************************************************/

#endif /* _KNOT_DEBUG_H_ */

/*! @} */
