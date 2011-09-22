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

#include "config.h" /* autoconf generated */

#include "knot/other/log.h"
#include "common/print.h"

/*! \todo Set these during configure as well. */
//#define KNOTD_SERVER_DEBUG
//#define KNOTD_THREADS_DEBUG
//#define KNOTD_JOURNAL_DEBUG
//#define KNOTD_NET_DEBUG
//#define KNOTD_ZONES_DEBUG
//#define KNOTD_XFR_DEBUG
//#define KNOTD_NOTIFY_DEBUG
//#define KNOTD_ZDUMP_DEBUG
//#define KNOTD_ZLOAD_DEBUG

/******************************************************************************/

#ifdef KNOTD_NOTIFY_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define debug_notify(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_notify_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_notify(msg...)
#define debug_notify_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define debug_notify_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_notify_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_notify_verb(msg...)
#define debug_notify_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define debug_notify_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_notify_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_notify_detail(msg...)
#define debug_notify_hex_detail(data, len)
#endif

/* No messages. */
#else
#define debug_notify(msg...)
#define debug_notify_hex(data, len)
#define debug_notify_verb(msg...)
#define debug_notify_hex_verb(data, len)
#define debug_notify_detail(msg...)
#define debug_notify_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_SERVER_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define debug_server(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_server_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_server(msg...)
#define debug_server_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define debug_server_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_server_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_server_verb(msg...)
#define debug_server_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define debug_server_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_server_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_server_detail(msg...)
#define debug_server_hex_detail(data, len)
#endif

/* No messages. */
#else
#define debug_server(msg...)
#define debug_server_hex(data, len)
#define debug_server_verb(msg...)
#define debug_server_hex_verb(data, len)
#define debug_server_detail(msg...)
#define debug_server_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_NET_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define debug_net(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_net_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_net(msg...)
#define debug_net_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define debug_net_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_net_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_net_verb(msg...)
#define debug_net_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define debug_net_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_net_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_net_detail(msg...)
#define debug_net_hex_detail(data, len)
#endif

/* No messages. */
#else
#define debug_net(msg...)
#define debug_net_hex(data, len)
#define debug_net_verb(msg...)
#define debug_net_hex_verb(data, len)
#define debug_net_detail(msg...)
#define debug_net_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_THREADS_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define debug_dt(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_dt_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_dt(msg...)
#define debug_dt_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define debug_dt_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_dt_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_dt_verb(msg...)
#define debug_dt_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define debug_dt_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_dt_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_dt_detail(msg...)
#define debug_dt_hex_detail(data, len)
#endif

/* No messages. */
#else
#define debug_dt(msg...)
#define debug_dt_hex(data, len)
#define debug_dt_verb(msg...)
#define debug_dt_hex_verb(data, len)
#define debug_dt_detail(msg...)
#define debug_dt_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_JOURNAL_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define debug_journal(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_journal_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_journal(msg...)
#define debug_journal_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define debug_journal_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_journal_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_journal_verb(msg...)
#define debug_journal_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define debug_journal_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_journal_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_journal_detail(msg...)
#define debug_journal_hex_detail(data, len)
#endif

/* No messages. */
#else
#define debug_journal(msg...)
#define debug_journal_hex(data, len)
#define debug_journal_verb(msg...)
#define debug_journal_hex_verb(data, len)
#define debug_journal_detail(msg...)
#define debug_journal_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_ZONES_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define debug_zones(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_zones_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_zones(msg...)
#define debug_zones_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define debug_zones_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_zones_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_zones_verb(msg...)
#define debug_zones_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define debug_zones_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_zones_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_zones_detail(msg...)
#define debug_zones_hex_detail(data, len)
#endif

/* No messages. */
#else
#define debug_zones(msg...)
#define debug_zones_hex(data, len)
#define debug_zones_verb(msg...)
#define debug_zones_hex_verb(data, len)
#define debug_zones_detail(msg...)
#define debug_zones_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_XFR_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define debug_xfr(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_xfr_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_xfr(msg...)
#define debug_xfr_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define debug_xfr_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_xfr_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_xfr_verb(msg...)
#define debug_xfr_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define debug_xfr_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_xfr_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_xfr_detail(msg...)
#define debug_xfr_hex_detail(data, len)
#endif

/* No messages. */
#else
#define debug_xfr(msg...)
#define debug_xfr_hex(data, len)
#define debug_xfr_verb(msg...)
#define debug_xfr_hex_verb(data, len)
#define debug_xfr_detail(msg...)
#define debug_xfr_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_ZDUMP_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define debug_zdump(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_zdump_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_zdump(msg...)
#define debug_zdump_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define debug_zdump_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_zdump_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_zdump_verb(msg...)
#define debug_zdump_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define debug_zdump_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_zdump_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_zdump_detail(msg...)
#define debug_zdump_hex_detail(data, len)
#endif

/* No messages. */
#else
#define debug_zdump(msg...)
#define debug_zdump_hex(data, len)
#define debug_zdump_verb(msg...)
#define debug_zdump_hex_verb(data, len)
#define debug_zdump_detail(msg...)
#define debug_zdump_hex_detail(data, len)
#endif

/******************************************************************************/

#ifdef KNOTD_ZLOAD_DEBUG

/* Brief messages. */
#ifdef DEBUG_ENABLE_BRIEF
#define debug_zload(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_zload_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_zload(msg...)
#define debug_zload_hex(data, len)
#endif

/* Verbose messages. */
#ifdef DEBUG_ENABLE_VERBOSE
#define debug_zload_verb(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_zload_hex_verb(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_zload_verb(msg...)
#define debug_zload_hex_verb(data, len)
#endif

/* Detail messages. */
#ifdef DEBUG_ENABLE_DETAILS
#define debug_zload_detail(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_zload_hex_detail(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_zload_detail(msg...)
#define debug_zload_hex_detail(data, len)
#endif

/* No messages. */
#else
#define debug_zload(msg...)
#define debug_zload_hex(data, len)
#define debug_zload_verb(msg...)
#define debug_zload_hex_verb(data, len)
#define debug_zload_detail(msg...)
#define debug_zload_hex_detail(data, len)
#endif

/******************************************************************************/

#endif /* _KNOTD_DEBUG_H_ */

/*! @} */
