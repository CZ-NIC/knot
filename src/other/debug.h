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
//#define DNSLIB_DNAME_DEBUG
//#define SERVER_DEBUG
//#define DT_DEBUG
//#define NET_DEBUG
//#define DNSLIB_DNAME_DEBUG

#define DNSLIB_ZONE_DEBUG
#define DNSLIB_RESPONSE_DEBUG
//#define MEM_DEBUG
//#define MEM_NOSLAB

#ifdef SERVER_DEBUG
#define debug_server(msg...) log_msg(LOG_DEBUG, msg)
#define debug_server_hex(data, len) hex_print((data), (len))
#else
#define debug_server(msg...)
#define debug_server_hex(data, len)
#endif

#ifdef DNSS_DEBUG
#define debug_dnss(msg...) log_msg(LOG_DEBUG, msg)
#define debug_dnss_hex(data, len) hex_print((data), (len))
#else
#define debug_dnss(msg...)
#define debug_dnss_hex(data, len)
#endif

#ifdef DNSLIB_DNAME_DEBUG
#define debug_dnslib_dname(msg...) log_msg(LOG_DEBUG, msg)
#else
#define debug_dnslib_dname(msg...)
#endif

#ifdef DNSLIB_ZONE_DEBUG
#define debug_dnslib_zone(msg...) log_msg(LOG_DEBUG, msg)
#else
#define debug_dnslib_zone(msg...)
#endif

#ifdef DNSLIB_RESPONSE_DEBUG
#define debug_dnslib_response(msg...) log_msg(LOG_DEBUG, msg)
#else
#define debug_dnslib_response(msg...)
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
#define debug_ns(msg...) log_msg(LOG_DEBUG, msg)
#define debug_ns_hex(data, len) hex_print((data), (len))
#else
#define debug_ns(msg...)
#define debug_ns_hex(data, len)
#endif

#ifdef ZDB_DEBUG
#define debug_zdb(msg...) log_msg(LOG_DEBUG, msg)
#define debug_zdb_hex(data, len) hex_print((data), (len))
#else
#define debug_zdb(msg...)
#define debug_zdb_hex(data, len)
#endif

#ifdef ZN_DEBUG
#define debug_zn(msg...) log_msg(LOG_DEBUG, msg)
#else
#define debug_zn(msg...)
#endif

#ifdef ZP_DEBUG
#define debug_zp(msg...) log_msg(LOG_DEBUG, msg)
#define debug_zp_hex(data, len) hex_print((data), (len))
#else
#define debug_zp(msg...)
#define debug_zp_hex(data, len)
#endif

#ifdef ZP_DEBUG_PARSE
#define debug_zp_parse(msg...) log_msg(LOG_DEBUG, msg)
#define debug_zp_parse_hex(data, len) hex_print((data), (len))
#else
#define debug_zp_parse(msg...)
#define debug_zp_parse_hex(data, len)
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
