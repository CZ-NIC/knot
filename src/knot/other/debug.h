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

#include "knot/other/log.h"
#include "common/print.h"

//#define KNOTD_NS_DEBUG
//#define KNOTD_SERVER_DEBUG
//#define KNOTD_THREADS_DEBUG
//#define KNOTD_JOURNAL_DEBUG
//#define KNOTD_NET_DEBUG
//#define KNOTD_ZONES_DEBUG
#define KNOTD_XFR_DEBUG
//#define KNOTD_NOTIFY_DEBUG
//#define KNOTD_ZDUMP_DEBUG
//#define KNOTD_ZLOAD_DEBUG

#ifdef KNOTD_NOTIFY_DEBUG
#define debug_notify(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_notify_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_notify(msg...)
#define debug_notify_hex(data, len)
#endif

#ifdef KNOTD_SERVER_DEBUG
#define debug_server(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_server_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_server(msg...)
#define debug_server_hex(data, len)
#endif

#ifdef KNOTD_NET_DEBUG
#define debug_net(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_net_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_net(msg...)
#define debug_net_hex(data, len)
#endif

#ifdef KNOTD_THREADS_DEBUG
#define debug_dt(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_dt_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_dt(msg...)
#define debug_dt_hex(data, len)
#endif

#ifdef KNOTD_JOURNAL_DEBUG
#define debug_journal(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#else
#define debug_journal(msg...)
#endif

#ifdef KNOTD_NS_DEBUG
#define debug_ns(msg...) log_msg(LOG_ANSWER, LOG_DEBUG, msg)
#define debug_ns_hex(data, len) hex_log(LOG_ANSWER, (data), (len))
#define DEBUG_NS(cmds) do { cmds } while (0)
#else
#define debug_ns(msg...)
#define debug_ns_hex(data, len)
#define DEBUG_NS(cmds)
#endif

#ifdef KNOTD_ZONES_DEBUG
#define debug_zones(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_zones_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#define DEBUG_zones(cmds) do { cmds } while (0)
#else
#define debug_zones(msg...)
#define debug_zones_hex(data, len)
#define DEBUG_zones(cmds)
#endif

#ifdef KNOTD_XFR_DEBUG
#define debug_xfr(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_xfr_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#define DEBUG_XFR(cmds) do { cmds } while (0)
#else
#define debug_xfr(msg...)
#define debug_xfr_hex(data, len)
#define DEBUG_XFR(cmds)
#endif

#ifdef KNOTD_ZDUMP_DEBUG
#define debug_knot_zdump(msg...) fprintf(stderr, msg)
#define DEBUG_KNOT_ZDUMP(cmds) do { cmds } while (0)
#else
#define debug_knot_zdump(msg...)
#define DEBUG_KNOT_ZDUMP(cmds)
#endif

#ifdef KNOTD_ZLOAD_DEBUG
#define debug_knot_zload(msg...) fprintf(stderr, msg)
#else
#define debug_knot_zload(msg...)
#endif


#endif /* _KNOTD_DEBUG_H_ */

/*! @} */
