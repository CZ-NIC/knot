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
#ifndef _CUTEDNS_DEBUG_H_
#define _CUTEDNS_DEBUG_H_

#include "log.h"
#include "print.h"

//#define ST_DEBUG
//#define SM_DEBUG
//#define DA_DEBUG
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
//#define DNSLIB_DNAME_DEBUG

//#define MEM_DEBUG
//#define MEM_NOSLAB
//#define MEM_POISON
//#define DNSLIB_ZONE_DEBUG
//#define DNSLIB_RESPONSE_DEBUG
//#define DNSLIB_ZONEDB_DEBUG
//#define DNSLIB_DNAME_DEBUG
//#define DNSLIB_ZONE_DEBUG
//#define DNSLIB_RESPONSE_DEBUG

#ifdef SERVER_DEBUG
#define debug_server(msg...) log_msg(LOG_DEBUG, msg)
#define debug_server_hex(data, len) hex_print((data), (len))
#else
#define debug_server(msg...)
#define debug_server_hex(data, len)
#endif

#ifdef DNSLIB_DNAME_DEBUG
#define debug_dnslib_dname(msg...) log_msg(LOG_ANSWER, LOG_DEBUG, msg)
#define debug_dnslib_dname_hex(data, len) hex_print((data), (len))
#define DEBUG_DNSLIB_DNAME(cmds) do { cmds } while (0)
#else
#define debug_dnslib_dname(msg...)
#define debug_dnslib_dname_hex(data, len)
#define DEBUG_DNSLIB_DNAME(cmds)
#endif

#ifdef DNSLIB_ZONE_DEBUG
#define debug_dnslib_zone(msg...) log_msg(LOG_ZONE, LOG_DEBUG, msg)
#define DEBUG_DNSLIB_ZONE(cmds) do { cmds } while (0)
#else
#define debug_dnslib_zone(msg...)
#define DEBUG_DNSLIB_ZONE(cmds)
#endif

#ifdef DNSLIB_ZONEDB_DEBUG
#define debug_dnslib_zonedb(msg...) log_msg(LOG_ZONE, LOG_DEBUG, msg)
#define DEBUG_DNSLIB_ZONEDB(cmds) do { cmds } while (0)
#else
#define debug_dnslib_zonedb(msg...)
#define DEBUG_DNSLIB_ZONEDB(cmds)
#endif

#ifdef DNSLIB_RESPONSE_DEBUG
#define debug_dnslib_response(msg...) log_msg(LOG_ANSWER, LOG_DEBUG, msg)
#define debug_dnslib_response_hex(data, len) hex_print((data), (len))
#define DEBUG_DNSLIB_RESPONSE(cmds) do { cmds } while (0)
#else
#define debug_dnslib_response(msg...)
#define debug_dnslib_response_hex(data, len)
#define DEBUG_DNSLIB_RESPONSE(cmds)
#endif

#ifdef CUCKOO_DEBUG
#define debug_ck(msg...) log_msg(LOG_DEBUG, msg)
#define debug_ck_hex(data, len) hex_print((data), (len))
#else
#define debug_ck(msg...)
#define debug_ck_hex(data, len)
#endif

#ifdef CUCKOO_DEBUG_HASH
#define debug_ck_hash(msg...) log_msg(LOG_DEBUG, msg)
#define debug_ck_hash_hex(data, len) hex_print((data), (len))
#define debug_ck_rehash(msg...) log_msg(LOG_DEBUG, msg)
#else
#define debug_ck_hash(msg...)
#define debug_ck_hash_hex(data, len)
#define debug_ck_rehash(msg...)
#endif

#ifdef DA_DEBUG
#define debug_da(msg...) log_msg(LOG_DEBUG, msg)
#else
#define debug_da(msg...)
#endif

#ifdef NET_DEBUG
#define debug_net(msg...) log_msg(LOG_DEBUG, msg)
#define debug_net_hex(data, len) hex_print((data), (len))
#else
#define debug_net(msg...)
#define debug_net_hex(data, len)
#endif

#ifdef DT_DEBUG
#define debug_dt(msg...) log_msg(LOG_DEBUG, msg)
#define debug_dt_hex(data, len) hex_print((data), (len))
#else
#define debug_dt(msg...)
#define debug_dt_hex(data, len)
#endif

#ifdef NS_DEBUG
#define debug_ns(msg...) log_msg(LOG_ANSWER, LOG_DEBUG, msg)
#define debug_ns_hex(data, len) hex_print((data), (len))
#define DEBUG_NS(cmds) do { cmds } while (0)
#else
#define debug_ns(msg...)
#define debug_ns_hex(data, len)
#define DEBUG_NS(cmds)
#endif

#ifdef ZP_DEBUG
#define debug_zp(msg...) log_msg(LOG_DEBUG, msg)
#define debug_zp_hex(data, len) hex_print((data), (len))
#else
#define debug_zp(msg...)
#define debug_zp_hex(data, len)
#endif

#ifdef ST_DEBUG
#define debug_st(msg...) log_msg(LOG_DEBUG, msg)
#else
#define debug_st(msg...)
#endif

#ifdef MEM_DEBUG
#define debug_mem(msg...) log_msg(LOG_DEBUG, msg)
#else
#define debug_mem(msg...)
#endif

#endif /* _CUTEDNS_DEBUG_H_ */

/*! @} */
