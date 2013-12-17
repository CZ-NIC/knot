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
 * \file other/debug.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Debugging facility, uses log.h.
 *
 * \addtogroup debugging
 * @{
 */

#ifndef _KNOTD_DEBUG_H_
#define _KNOTD_DEBUG_H_

#ifdef KNOTD_SERVER_DEBUG
  #define KNOTD_THREADS_DEBUG
  #define KNOTD_JOURNAL_DEBUG
  #define KNOTD_NET_DEBUG
  #define KNOTD_RRL_DEBUG
#endif

#ifdef KNOT_ZONES_DEBUG
  #define KNOTD_ZONES_DEBUG
#endif

#ifdef KNOT_XFR_DEBUG
  #define KNOTD_XFR_DEBUG
  #define KNOTD_NOTIFY_DEBUG
#endif

#ifdef KNOT_LOADER_DEBUG
  #define KNOTD_ZLOAD_DEBUG
  #define KNOTD_SEMCHECK_DEBUG
#endif

#include "common/log.h"
#include "common/print.h"

/******************************************************************************/

#ifdef KNOTD_NOTIFY_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_notify(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_notify_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_notify(msg...)
#define dbg_notify_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_notify_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_notify_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_notify_verb(msg...)
#define dbg_notify_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_notify_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_notify_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_notify_detail(msg...)
#define dbg_notify_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_notify(msg...)
#define dbg_notify_hex(data, len)
#define dbg_notify_verb(msg...)
#define dbg_notify_hex_verb(data, len)
#define dbg_notify_detail(msg...)
#define dbg_notify_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_SERVER_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_server(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_server_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_server(msg...)
#define dbg_server_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_server_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_server_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_server_verb(msg...)
#define dbg_server_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_server_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_server_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
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
#define dbg_net(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_net_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_net(msg...)
#define dbg_net_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_net_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_net_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_net_verb(msg...)
#define dbg_net_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_net_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_net_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
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
#define dbg_rrl(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_rrl_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_rrl(msg...)
#define dbg_rrl_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_rrl_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_rrl_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_rrl_verb(msg...)
#define dbg_rrl_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_rrl_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_rrl_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
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
#define dbg_dt(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_dt_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_dt(msg...)
#define dbg_dt_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_dt_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_dt_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_dt_verb(msg...)
#define dbg_dt_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_dt_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_dt_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
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
#define dbg_journal(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_journal_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_journal(msg...)
#define dbg_journal_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_journal_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_journal_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_journal_verb(msg...)
#define dbg_journal_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_journal_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_journal_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
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

#ifdef KNOTD_ZONES_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_zones(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_zones_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#define dbg_zones_exec(cmds) do { cmds } while (0)
#else
#define dbg_zones(msg...)
#define dbg_zones_hex(data, len)
#define dbg_zones_exec(cmds)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_zones_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_zones_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#define dbg_zones_exec_verb(cmds) do { cmds } while (0)
#else
#define dbg_zones_verb(msg...)
#define dbg_zones_hex_verb(data, len)
#define dbg_zones_exec_verb(cmds)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_zones_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_zones_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
#define dbg_zones_exec_detail(cmds) do { cmds } while (0)
#else
#define dbg_zones_detail(msg...)
#define dbg_zones_hex_detail(data, len)
#define dbg_zones_exec_detail(cmds)
#endif

/* No messages. */
#else
#define dbg_zones(msg...)
#define dbg_zones_hex(data, len)
#define dbg_zones_verb(msg...)
#define dbg_zones_hex_verb(data, len)
#define dbg_zones_detail(msg...)
#define dbg_zones_hex_detail(data, len)
#define dbg_zones_exec(cmds)
#endif

/******************************************************************************/

#ifdef KNOTD_XFR_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_xfr(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_xfr_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_xfr(msg...)
#define dbg_xfr_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_xfr_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_xfr_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_xfr_verb(msg...)
#define dbg_xfr_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_xfr_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_xfr_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_xfr_detail(msg...)
#define dbg_xfr_hex_detail(data, len)
#endif

/* No messages. */
#else
#define dbg_xfr(msg...)
#define dbg_xfr_hex(data, len)
#define dbg_xfr_verb(msg...)
#define dbg_xfr_hex_verb(data, len)
#define dbg_xfr_detail(msg...)
#define dbg_xfr_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_ZLOAD_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define dbg_zload(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_zload_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_zload(msg...)
#define dbg_zload_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_zload_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_zload_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_zload_verb(msg...)
#define dbg_zload_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_zload_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_zload_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
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
#define dbg_semcheck(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_semcheck_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_semcheck(msg...)
#define dbg_semcheck_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define dbg_semcheck_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_semcheck_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define dbg_semcheck_verb(msg...)
#define dbg_semcheck_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define dbg_semcheck_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define dbg_semcheck_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
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

#endif /* _KNOTD_DEBUG_H_ */

/*! @} */
