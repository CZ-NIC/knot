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
/*!
 * \file common/debug.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Debugging facility, uses log.h.
 *
 * \addtogroup debugging
 * @{
 */

#pragma once

#include <stdint.h>
#include <stdio.h>

#include "knot/common/log.h"
#include "libknot/internal/print.h"

#ifdef KNOTD_SERVER_DEBUG
  #define KNOTD_THREADS_DEBUG
  #define KNOTD_JOURNAL_DEBUG
  #define KNOTD_NET_DEBUG
  #define KNOTD_RRL_DEBUG
#endif

#ifdef KNOT_LOADER_DEBUG
  #define KNOTD_ZLOAD_DEBUG
  #define KNOTD_SEMCHECK_DEBUG
#endif

#ifdef KNOT_ZONES_DEBUG
  #define KNOT_ZONE_DEBUG
  #define KNOT_ZONEDIFF_DEBUG
#endif

/******************************************************************************/

#ifdef KNOT_NS_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_ns(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_ns_hex(data, len)  hex_log((data), (len))
#define dbg_ns_exec(cmds) do { cmds } while (0)
#else
#define dbg_ns(msg...)
#define dbg_ns_hex(data, len)
#define dbg_ns_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_ns_verb(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_ns_hex_verb(data, len) hex_log((data), (len))
#define dbg_ns_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_ns_verb(msg...)
#define dbg_ns_hex_verb(data, len)
#define dbg_ns_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_ns_detail(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_ns_hex_detail(data, len)  hex_log((data), (len))
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

#ifdef KNOT_ZONE_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_zone(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_zone_hex(data, len)  hex_log((data), (len))
#define dbg_zone_exec(cmds) do { cmds } while (0)
#else
#define dbg_zone(msg...)
#define dbg_zone_hex(data, len)
#define dbg_zone_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_zone_verb(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_zone_hex_verb(data, len)  hex_log((data), (len))
#define dbg_zone_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_zone_verb(msg...)
#define dbg_zone_hex_verb(data, len)
#define dbg_zone_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_zone_detail(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_zone_hex_detail(data, len)  hex_log((data), (len))
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

#ifdef KNOT_ZONEDIFF_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_zonediff(msg...) fprintf(stderr, msg)
#define dbg_zonediff_hex(data, len)  hex_print((data), (len))
#else
#define dbg_zonediff(msg...)
#define dbg_zonediff_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_zonediff_verb(msg...) fprintf(stderr, msg)
#define dbg_zonediff_hex_verb(data, len)  hex_print((data), (len))
#else
#define dbg_zonediff_verb(msg...)
#define dbg_zonediff_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_zonediff_detail(msg...) fprintf(stderr, msg)
#define dbg_zonediff_hex_detail(data, len)  hex_print((data), (len))
#define dbg_zonediff_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_zonediff_detail(msg...)
#define dbg_zonediff_hex_detail(data, len)
#define dbg_zonediff_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_zonediff(msg...)
#define dbg_zonediff_hex(data, len)
#define dbg_zonediff_verb(msg...)
#define dbg_zonediff_hex_verb(data, len)
#define dbg_zonediff_detail(msg...)
#define dbg_zonediff_hex_detail(data, len)
#define dbg_zonediff_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOT_DNSSEC_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_dnssec(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_dnssec_hex(data, len)  hex_log((data), (len))
#define dbg_dnssec_exec(cmds) do { cmds } while (0)
#else
#define dbg_dnssec(msg...)
#define dbg_dnssec_hex(data, len)
#define dbg_dnssec_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_dnssec_verb(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_dnssec_hex_verb(data, len) hex_log((data), (len))
#define dbg_dnssec_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_dnssec_verb(msg...)
#define dbg_dnssec_hex_verb(data, len)
#define dbg_dnssec_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_dnssec_detail(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_dnssec_hex_detail(data, len)  hex_log((data), (len))
#define dbg_dnssec_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_dnssec_detail(msg...)
#define dbg_dnssec_hex_detail(data, len)
#define dbg_dnssec_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_dnssec(msg...)
#define dbg_dnssec_hex(data, len)
#define dbg_dnssec_exec(cmds)
#define dbg_dnssec_verb(msg...)
#define dbg_dnssec_hex_verb(data, len)
#define dbg_dnssec_exec_verb(cmds)
#define dbg_dnssec_detail(msg...)
#define dbg_dnssec_hex_detail(data, len)
#define dbg_dnssec_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOTD_SERVER_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_server(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_server_hex(data, len) hex_log((data), (len))
#else
#define dbg_server(msg...)
#define dbg_server_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_server_verb(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_server_hex_verb(data, len) hex_log((data), (len))
#else
#define dbg_server_verb(msg...)
#define dbg_server_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_server_detail(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_server_hex_detail(data, len) hex_log((data), (len))
#else
#define dbg_server_detail(msg...)
#define dbg_server_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_server(msg...)
#define dbg_server_hex(data, len)
#define dbg_server_verb(msg...)
#define dbg_server_hex_verb(data, len)
#define dbg_server_detail(msg...)
#define dbg_server_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_NET_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_net(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_net_hex(data, len) hex_log((data), (len))
#else
#define dbg_net(msg...)
#define dbg_net_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_net_verb(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_net_hex_verb(data, len) hex_log((data), (len))
#else
#define dbg_net_verb(msg...)
#define dbg_net_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_net_detail(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_net_hex_detail(data, len) hex_log((data), (len))
#else
#define dbg_net_detail(msg...)
#define dbg_net_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_net(msg...)
#define dbg_net_hex(data, len)
#define dbg_net_verb(msg...)
#define dbg_net_hex_verb(data, len)
#define dbg_net_detail(msg...)
#define dbg_net_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_RRL_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_rrl(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_rrl_hex(data, len) hex_log((data), (len))
#else
#define dbg_rrl(msg...)
#define dbg_rrl_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_rrl_verb(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_rrl_hex_verb(data, len) hex_log((data), (len))
#else
#define dbg_rrl_verb(msg...)
#define dbg_rrl_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_rrl_detail(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_rrl_hex_detail(data, len) hex_log((data), (len))
#else
#define dbg_rrl_detail(msg...)
#define dbg_rrl_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_rrl(msg...)
#define dbg_rrl_hex(data, len)
#define dbg_rrl_verb(msg...)
#define dbg_rrl_hex_verb(data, len)
#define dbg_rrl_detail(msg...)
#define dbg_rrl_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_THREADS_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_dt(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_dt_hex(data, len) hex_log((data), (len))
#else
#define dbg_dt(msg...)
#define dbg_dt_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_dt_verb(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_dt_hex_verb(data, len) hex_log((data), (len))
#else
#define dbg_dt_verb(msg...)
#define dbg_dt_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_dt_detail(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_dt_hex_detail(data, len) hex_log((data), (len))
#else
#define dbg_dt_detail(msg...)
#define dbg_dt_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_dt(msg...)
#define dbg_dt_hex(data, len)
#define dbg_dt_verb(msg...)
#define dbg_dt_hex_verb(data, len)
#define dbg_dt_detail(msg...)
#define dbg_dt_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_JOURNAL_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_journal(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_journal_hex(data, len) hex_log((data), (len))
#else
#define dbg_journal(msg...)
#define dbg_journal_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_journal_verb(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_journal_hex_verb(data, len) hex_log((data), (len))
#else
#define dbg_journal_verb(msg...)
#define dbg_journal_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_journal_detail(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_journal_hex_detail(data, len) hex_log((data), (len))
#else
#define dbg_journal_detail(msg...)
#define dbg_journal_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_journal(msg...)
#define dbg_journal_hex(data, len)
#define dbg_journal_verb(msg...)
#define dbg_journal_hex_verb(data, len)
#define dbg_journal_detail(msg...)
#define dbg_journal_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_ZLOAD_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_zload(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_zload_hex(data, len) hex_log((data), (len))
#else
#define dbg_zload(msg...)
#define dbg_zload_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_zload_verb(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_zload_hex_verb(data, len) hex_log((data), (len))
#else
#define dbg_zload_verb(msg...)
#define dbg_zload_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_zload_detail(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_zload_hex_detail(data, len) hex_log((data), (len))
#define dbg_zload_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_zload_detail(msg...)
#define dbg_zload_hex_detail(data, len)
#define dbg_zload_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_zload(msg...)
#define dbg_zload_hex(data, len)
#define dbg_zload_verb(msg...)
#define dbg_zload_hex_verb(data, len)
#define dbg_zload_detail(msg...)
#define dbg_zload_hex_detail(data, len)
#define dbg_zload_exec_detail(cmds)
#endif

/******************************************************************************/

#ifdef KNOTD_SEMCHECK_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_semcheck(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_semcheck_hex(data, len) hex_log((data), (len))
#else
#define dbg_semcheck(msg...)
#define dbg_semcheck_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_semcheck_verb(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_semcheck_hex_verb(data, len) hex_log((data), (len))
#else
#define dbg_semcheck_verb(msg...)
#define dbg_semcheck_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_semcheck_detail(msg...) log_msg(LOG_DEBUG, msg)
#define dbg_semcheck_hex_detail(data, len) hex_log((data), (len))
#define dbg_semcheck_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_semcheck_detail(msg...)
#define dbg_semcheck_hex_detail(data, len)
#define dbg_semcheck_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_semcheck(msg...)
#define dbg_semcheck_hex(data, len)
#define dbg_semcheck_verb(msg...)
#define dbg_semcheck_hex_verb(data, len)
#define dbg_semcheck_detail(msg...)
#define dbg_semcheck_hex_detail(data, len)
#define dbg_semcheck_exec_detail(cmds)
#endif

/******************************************************************************/

/*! @} */
