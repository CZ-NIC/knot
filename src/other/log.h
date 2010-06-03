/** \file log.h
  * Logging facility.
  */
#ifndef __log_h__
#define __log_h__

/* Loglevel defined in syslog.h, may be redefined in other backend, but keep naming.
 * LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG
 */
#include <syslog.h>

/* Logging facility setup. */
int log_open(int print_mask, int log_mask);
int log_close();

/* Logging functions. */
int print_msg(int level, const char* msg, ...) __attribute__((format (printf, 2, 3)));
#define log_msg(level, msg...) \
    syslog((level), msg); \
    print_msg((level), msg)

/* Convenient logging. */
#define log_error(msg...) log_msg(LOG_ERR, msg)
#define log_warning(msg...) log_msg(LOG_WARNING, msg)
#define log_notice(msg...) log_msg(LOG_NOTICE, msg)
#define log_info(msg...) log_msg(LOG_INFO, msg)
#define log_debug(msg...) log_msg(LOG_DEBUG, msg)

/* Conditional logging. */
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

#endif // __print_h__
