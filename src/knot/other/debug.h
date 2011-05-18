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

#ifndef _KNOT_DEBUG_H_
#define _KNOT_DEBUG_H_

#include "knot/other/log.h"
#include "common/print.h"

//#define SM_DEBUG
//#define NS_DEBUG
//#define SERVER_DEBUG
//#define DT_DEBUG
//#define NET_DEBUG
//#define ZONES_DEBUG
#define XFR_DEBUG

#ifdef SERVER_DEBUG
#define debug_server(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_server_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_server(msg...)
#define debug_server_hex(data, len)
#endif

#ifdef NET_DEBUG
#define debug_net(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_net_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_net(msg...)
#define debug_net_hex(data, len)
#endif

#ifdef DT_DEBUG
#define debug_dt(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_dt_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_dt(msg...)
#define debug_dt_hex(data, len)
#endif

#ifdef NS_DEBUG
#define debug_ns(msg...) log_msg(LOG_ANSWER, LOG_DEBUG, msg)
#define debug_ns_hex(data, len) hex_log(LOG_ANSWER, (data), (len))
#define DEBUG_NS(cmds) do { cmds } while (0)
#else
#define debug_ns(msg...)
#define debug_ns_hex(data, len)
#define DEBUG_NS(cmds)
#endif

#ifdef ZONES_DEBUG
#define debug_zones(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_zones_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#define DEBUG_zones(cmds) do { cmds } while (0)
#else
#define debug_zones(msg...)
#define debug_zones_hex(data, len)
#define DEBUG_zones(cmds)
#endif

#ifdef XFR_DEBUG
#define debug_xfr(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_xfr_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#define DEBUG_XFR(cmds) do { cmds } while (0)
#else
#define debug_xfr(msg...)
#define debug_xfr_hex(data, len)
#define DEBUG_XFR(cmds)
#endif

#endif /* _KNOT_DEBUG_H_ */

/*! @} */
