/*!
 * \file debug.h
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

#include "other/log.h"
#include "other/print.h"

//#define SM_DEBUG
//#define CUCKOO_DEBUG
//#define CUCKOO_DEBUG_HASH
//#define ZP_DEBUG
//#define NS_DEBUG
//#define ZDB_DEBUG
//#define ZDB_DEBUG_INSERT_CHECK
//#define ZN_DEBUG
//#define ZP_DEBUG_PARSE
//#define SERVER_DEBUG
//#define DT_DEBUG
//#define NET_DEBUG

#ifdef SERVER_DEBUG
#define debug_server(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_server_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#else
#define debug_server(msg...)
#define debug_server_hex(data, len)
#endif

#ifdef CUCKOO_DEBUG
#define debug_ck(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#else
#define debug_ck(msg...)
#endif

#ifdef CUCKOO_DEBUG_HASH
#define debug_ck_hash(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#define debug_ck_hash_hex(data, len) hex_log(LOG_SERVER, (data), (len))
#define debug_ck_rehash(msg...) log_msg(LOG_SERVER, LOG_DEBUG, msg)
#else
#define debug_ck_hash(msg...)
#define debug_ck_hash_hex(data, len)
#define debug_ck_rehash(msg...)
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

#ifdef ZP_DEBUG
#define debug_zp(msg...) log_msg(LOG_ZONE, LOG_DEBUG, msg)
#define debug_zp_hex(data, len) hex_log(LOG_ZONE, (data), (len))
#else
#define debug_zp(msg...)
#define debug_zp_hex(data, len)
#endif

#endif /* _KNOT_DEBUG_H_ */

/*! @} */
