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
/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
//#define KNOT_RDATA_DEBUG
//#define KNOT_NSEC3_DEBUG
//#define CUCKOO_DEBUG
//#define CUCKOO_DEBUG_HASH
//#define KNOT_NS_DEBUG
//#define KNOT_XFRIN_DEBUG
//#define KNOT_DDNS_DEBUG
//#define KNOT_TSIG_DEBUG

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
#define dbg_ns(msg...) fprintf(stderr, msg)
#define dbg_ns_hex(data, len)  hex_print((data), (len))
#define dbg_ns_exec(cmds) do { cmds } while (0)
#else
#define dbg_ns(msg...)
#define dbg_ns_hex(data, len)
#define dbg_ns_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_ns_verb(msg...) fprintf(stderr, msg)
#define dbg_ns_hex_verb(data, len)  hex_print((data), (len))
#define dbg_ns_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_ns_verb(msg...)
#define dbg_ns_hex_verb(data, len)
#define dbg_ns_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_ns_detail(msg...) fprintf(stderr, msg)
#define dbg_ns_hex_detail(data, len)  hex_print((data), (len))
#define dbg_ns_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_ns_detail(msg...)
#define dbg_ns_hex_detail(data, len)
#define dbg_ns_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_ns(msg...)
#define dbg_ns_hex(data, len)
#define dbg_ns_exec(cmds)
#define dbg_ns_verb(msg...)
#define dbg_ns_hex_verb(data, len)
#define dbg_ns_exec_verb(cmds)
#define dbg_ns_detail(msg...)
#define dbg_ns_hex_detail(data, len)
#define dbg_ns_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_DNAME_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_dname(msg...) fprintf(stderr, msg)
#define dbg_dname_hex(data, len)  hex_print((data), (len))
#define dbg_dname_exec(cmds) do { cmds } while (0)
#else
#define dbg_dname(msg...)
#define dbg_dname_hex(data, len)
#define dbg_dname_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_dname_verb(msg...) fprintf(stderr, msg)
#define dbg_dname_hex_verb(data, len)  hex_print((data), (len))
#define dbg_dname_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_dname_verb(msg...)
#define dbg_dname_hex_verb(data, len)
#define dbg_dname_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_dname_detail(msg...) fprintf(stderr, msg)
#define dbg_dname_hex_detail(data, len)  hex_print((data), (len))
#define dbg_dname_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_dname_detail(msg...)
#define dbg_dname_hex_detail(data, len)
#define dbg_dname_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_dname(msg...)
#define dbg_dname_hex(data, len)
#define dbg_dname_exec(cmds)
#define dbg_dname_verb(msg...)
#define dbg_dname_hex_verb(data, len)
#define dbg_dname_exec_verb(cmds)
#define dbg_dname_detail(msg...)
#define dbg_dname_hex_detail(data, len)
#define dbg_dname_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_NODE_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_node(msg...) fprintf(stderr, msg)
#define dbg_node_hex(data, len)  hex_print((data), (len))
#else
#define dbg_node(msg...)
#define dbg_node_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_node_verb(msg...) fprintf(stderr, msg)
#define dbg_node_hex_verb(data, len)  hex_print((data), (len))
#else
#define dbg_node_verb(msg...)
#define dbg_node_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_node_detail(msg...) fprintf(stderr, msg)
#define dbg_node_hex_detail(data, len)  hex_print((data), (len))
#else
#define dbg_node_detail(msg...)
#define dbg_node_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_node(msg...)
#define dbg_node_hex(data, len)
#define dbg_node_verb(msg...)
#define dbg_node_hex_verb(data, len)
#define dbg_node_detail(msg...)
#define dbg_node_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOT_ZONE_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_zone(msg...) fprintf(stderr, msg)
#define dbg_zone_hex(data, len)  hex_print((data), (len))
#define dbg_zone_exec(cmds) do { cmds } while (0)
#else
#define dbg_zone(msg...)
#define dbg_zone_hex(data, len)
#define dbg_zone_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_zone_verb(msg...) fprintf(stderr, msg)
#define dbg_zone_hex_verb(data, len)  hex_print((data), (len))
#define dbg_zone_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_zone_verb(msg...)
#define dbg_zone_hex_verb(data, len)
#define dbg_zone_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_zone_detail(msg...) fprintf(stderr, msg)
#define dbg_zone_hex_detail(data, len)  hex_print((data), (len))
#define dbg_zone_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_zone_detail(msg...)
#define dbg_zone_hex_detail(data, len)
#define dbg_zone_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_zone(msg...)
#define dbg_zone_hex(data, len)
#define dbg_zone_exec(cmds)
#define dbg_zone_verb(msg...)
#define dbg_zone_hex_verb(data, len)
#define dbg_zone_exec_verb(cmds)
#define dbg_zone_detail(msg...)
#define dbg_zone_hex_detail(data, len)
#define dbg_zone_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_ZONEDB_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_zonedb(msg...) fprintf(stderr, msg)
#define dbg_zonedb_hex(data, len)  hex_print((data), (len))
#define dbg_zonedb_exec(cmds) do { cmds } while (0)
#else
#define dbg_zonedb(msg...)
#define dbg_zonedb_hex(data, len)
#define dbg_zonedb_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_zonedb_verb(msg...) fprintf(stderr, msg)
#define dbg_zonedb_hex_verb(data, len)  hex_print((data), (len))
#define dbg_zonedb_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_zonedb_verb(msg...)
#define dbg_zonedb_hex_verb(data, len)
#define dbg_zonedb_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_zonedb_detail(msg...) fprintf(stderr, msg)
#define dbg_zonedb_hex_detail(data, len)  hex_print((data), (len))
#define dbg_zonedb_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_zonedb_detail(msg...)
#define dbg_zonedb_hex_detail(data, len)
#define dbg_zonedb_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_zonedb(msg...)
#define dbg_zonedb_hex(data, len)
#define dbg_zonedb_exec(cmds)
#define dbg_zonedb_verb(msg...)
#define dbg_zonedb_hex_verb(data, len)
#define dbg_zonedb_exec_verb(cmds)
#define dbg_zonedb_detail(msg...)
#define dbg_zonedb_hex_detail(data, len)
#define dbg_zonedb_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_RESPONSE_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_response(msg...) fprintf(stderr, msg)
#define dbg_response_hex(data, len)  hex_print((data), (len))
#define dbg_response_exec(cmds) do { cmds } while (0)
#else
#define dbg_response(msg...)
#define dbg_response_hex(data, len)
#define dbg_response_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_response_verb(msg...) fprintf(stderr, msg)
#define dbg_response_hex_verb(data, len)  hex_print((data), (len))
#define dbg_response_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_response_verb(msg...)
#define dbg_response_hex_verb(data, len)
#define dbg_response_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_response_detail(msg...) fprintf(stderr, msg)
#define dbg_response_hex_detail(data, len)  hex_print((data), (len))
#define dbg_response_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_response_detail(msg...)
#define dbg_response_hex_detail(data, len)
#define dbg_response_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_response(msg...)
#define dbg_response_hex(data, len)
#define dbg_response_exec(cmds)
#define dbg_response_verb(msg...)
#define dbg_response_hex_verb(data, len)
#define dbg_response_exec_verb(cmds)
#define dbg_response_detail(msg...)
#define dbg_response_hex_detail(data, len)
#define dbg_response_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_PACKET_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_packet(msg...) fprintf(stderr, msg)
#define dbg_packet_hex(data, len)  hex_print((data), (len))
#define dbg_packet_exec(cmds) do { cmds } while (0)
#else
#define dbg_packet(msg...)
#define dbg_packet_hex(data, len)
#define dbg_packet_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_packet_verb(msg...) fprintf(stderr, msg)
#define dbg_packet_hex_verb(data, len)  hex_print((data), (len))
#define dbg_packet_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_packet_verb(msg...)
#define dbg_packet_hex_verb(data, len)
#define dbg_packet_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_packet_detail(msg...) fprintf(stderr, msg)
#define dbg_packet_hex_detail(data, len)  hex_print((data), (len))
#define dbg_packet_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_packet_detail(msg...)
#define dbg_packet_hex_detail(data, len)
#define dbg_packet_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_packet(msg...)
#define dbg_packet_hex(data, len)
#define dbg_packet_exec(cmds)
#define dbg_packet_verb(msg...)
#define dbg_packet_hex_verb(data, len)
#define dbg_packet_exec_verb(cmds)
#define dbg_packet_detail(msg...)
#define dbg_packet_hex_detail(data, len)
#define dbg_packet_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_EDNS_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_edns(msg...) fprintf(stderr, msg)
#define dbg_edns_hex(data, len)  hex_print((data), (len))
#else
#define dbg_edns(msg...)
#define dbg_edns_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_edns_verb(msg...) fprintf(stderr, msg)
#define dbg_edns_hex_verb(data, len)  hex_print((data), (len))
#else
#define dbg_edns_verb(msg...)
#define dbg_edns_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_edns_detail(msg...) fprintf(stderr, msg)
#define dbg_edns_hex_detail(data, len)  hex_print((data), (len))
#else
#define dbg_edns_detail(msg...)
#define dbg_edns_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_edns(msg...)
#define dbg_edns_hex(data, len)
#define dbg_edns_verb(msg...)
#define dbg_edns_hex_verb(data, len)
#define dbg_edns_detail(msg...)
#define dbg_edns_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOT_NSEC3_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_nsec3(msg...) fprintf(stderr, msg)
#define dbg_nsec3_hex(data, len)  hex_print((data), (len))
#else
#define dbg_nsec3(msg...)
#define dbg_nsec3_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_nsec3_verb(msg...) fprintf(stderr, msg)
#define dbg_nsec3_hex_verb(data, len)  hex_print((data), (len))
#else
#define dbg_nsec3_verb(msg...)
#define dbg_nsec3_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_nsec3_detail(msg...) fprintf(stderr, msg)
#define dbg_nsec3_hex_detail(data, len)  hex_print((data), (len))
#else
#define dbg_nsec3_detail(msg...)
#define dbg_nsec3_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_nsec3(msg...)
#define dbg_nsec3_hex(data, len)
#define dbg_nsec3_verb(msg...)
#define dbg_nsec3_hex_verb(data, len)
#define dbg_nsec3_detail(msg...)
#define dbg_nsec3_hex_detail(data, len)
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

#ifdef KNOT_XFRIN_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_xfrin(msg...) fprintf(stderr, msg)
#define dbg_xfrin_hex(data, len)  hex_print((data), (len))
#define dbg_xfrin_exec(cmds) do { cmds } while (0)
#else
#define dbg_xfrin(msg...)
#define dbg_xfrin_hex(data, len)
#define dbg_xfrin_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_xfrin_verb(msg...) fprintf(stderr, msg)
#define dbg_xfrin_hex_verb(data, len)  hex_print((data), (len))
#define dbg_xfrin_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_xfrin_verb(msg...)
#define dbg_xfrin_hex_verb(data, len)
#define dbg_xfrin_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_xfrin_detail(msg...) fprintf(stderr, msg)
#define dbg_xfrin_hex_detail(data, len)  hex_print((data), (len))
#define dbg_xfrin_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_xfrin_detail(msg...)
#define dbg_xfrin_hex_detail(data, len)
#define dbg_xfrin_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_xfrin(msg...)
#define dbg_xfrin_hex(data, len)
#define dbg_xfrin_exec(cmds)
#define dbg_xfrin_verb(msg...)
#define dbg_xfrin_hex_verb(data, len)
#define dbg_xfrin_exec_verb(cmds)
#define dbg_xfrin_detail(msg...)
#define dbg_xfrin_hex_detail(data, len)
#define dbg_xfrin_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_DDNS_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_ddns(msg...) fprintf(stderr, msg)
#define dbg_ddns_hex(data, len)  hex_print((data), (len))
#else
#define dbg_ddns(msg...)
#define dbg_ddns_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_ddns_verb(msg...) fprintf(stderr, msg)
#define dbg_ddns_hex_verb(data, len)  hex_print((data), (len))
#else
#define dbg_ddns_verb(msg...)
#define dbg_ddns_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_ddns_detail(msg...) fprintf(stderr, msg)
#define dbg_ddns_hex_detail(data, len)  hex_print((data), (len))
#else
#define dbg_ddns_detail(msg...)
#define dbg_ddns_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_ddns(msg...)
#define dbg_ddns_hex(data, len)
#define dbg_ddns_verb(msg...)
#define dbg_ddns_hex_verb(data, len)
#define dbg_ddns_detail(msg...)
#define dbg_ddns_hex_detail(data, len)
#endif

#ifdef KNOT_TSIG_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_tsig(msg...) fprintf(stderr, msg)
#define dbg_tsig_hex(data, len)  hex_print((const char*)(data), (len))
#else
#define dbg_tsig(msg...)
#define dbg_tsig_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_tsig_verb(msg...) fprintf(stderr, msg)
#define dbg_tsig_hex_verb(data, len)  hex_print((const char*)(data), (len))
#else
#define dbg_tsig_verb(msg...)
#define dbg_tsig_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_tsig_detail(msg...) fprintf(stderr, msg)
#define dbg_tsig_hex_detail(data, len)  hex_print((const char*)(data), (len))
#else
#define dbg_tsig_detail(msg...)
#define dbg_tsig_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_tsig(msg...)
#define dbg_tsig_hex(data, len)
#define dbg_tsig_verb(msg...)
#define dbg_tsig_hex_verb(data, len)
#define dbg_tsig_detail(msg...)
#define dbg_tsig_hex_detail(data, len)
#endif

#ifdef KNOT_RRSET_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_rrset(msg...) fprintf(stderr, msg)
#define dbg_rrset_hex(data, len)  hex_print((data), (len))
#else
#define dbg_rrset(msg...)
#define dbg_rrset_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_rrset_verb(msg...) fprintf(stderr, msg)
#define dbg_rrset_hex_verb(data, len)  hex_print((data), (len))
#else
#define dbg_rrset_verb(msg...)
#define dbg_rrset_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_rrset_detail(msg...) fprintf(stderr, msg)
#define dbg_rrset_hex_detail(data, len)  hex_print((data), (len))
#else
#define dbg_rrset_detail(msg...)
#define dbg_rrset_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_rrset(msg...)
#define dbg_rrset_hex(data, len)
#define dbg_rrset_verb(msg...)
#define dbg_rrset_hex_verb(data, len)
#define dbg_rrset_detail(msg...)
#define dbg_rrset_hex_detail(data, len)
#endif

/******************************************************************************/

#endif /* _KNOT_DEBUG_H_ */

/*! @} */
