/** \file debug.h
  * Debugging facility, uses log.h.
  */
#ifndef __debug_h__
#define __debug_h__
#include "log.h"

//#define DA_DEBUG
//#define CUCKOO_DEBUG
//#define CUCKOO_DEBUG_HASH
//#define ZP_DEBUG
//#define NS_DEBUG
//#define ZDB_DEBUG
//#define ZP_DEBUG_PARSE

#ifdef CUTE_DEBUG
#define debug_server(msg...) log_msg(LOG_DEBUG, msg)
#else
#define debug_server(msg...)
#endif

#ifdef DNSS_DEBUG
#define debug_dnss(msg...) log_msg(LOG_DEBUG, msg)
#define debug_dnss_hex(data, len) hex_print((data), (len))
#else
#define debug_dnss(msg...)
#define debug_dnss_hex(data, len)
#endif

#ifdef CUCKOO_DEBUG
#define debug_cuckoo(msg...) log_msg(LOG_DEBUG, msg)
#define debug_cuckoo_hex(data, len) hex_print((data), (len))
#else
#define debug_cuckoo(msg...)
#define debug_cuckoo_hex(data, len)
#endif

#ifdef CUCKOO_DEBUG_HASH
#define debug_cuckoo_hash(msg...) log_msg(LOG_DEBUG, msg)
#define debug_cuckoo_hash_hex(data, len) hex_print((data), (len))
#define debug_cuckoo_rehash(msg...) log_msg(LOG_DEBUG, msg)
#else
#define debug_cuckoo_hash(msg...)
#define debug_cuckoo_hash_hex(data, len)
#define debug_cuckoo_rehash(msg...)
#endif

#ifdef DA_DEBUG
#define debug_da(msg...) log_msg(LOG_DEBUG, msg)
#else
#define debug_da(msg...)
#endif

#ifdef SM_DEBUG
#define debug_sm(msg...) log_msg(LOG_DEBUG, msg)
#define debug_sm_hex(data, len) hex_print((data), (len))
#else
#define debug_sm(msg...)
#define debug_sm_hex(data, len)
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

#endif // __debug_h__
