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

/*! Open log and stdio output for given masks.
 *  For bitmasks, refer to syslog.h
 *  @see syslog.h
 * \return always 0
 */
int log_open(int print_mask, int log_mask);

/*! Close log and stdio output.
 * \return always 0
 */
int log_close();

/*! Return positive number if open.
 * \return 1 if open (boolean true)
 * \return 0 if closed (boolean false)
 */
int log_isopen();

/* Logging functions. */
int print_msg(int level, const char* msg, ...) __attribute__((format (printf, 2, 3)));
#define log_msg(level, msg...) \
    if(log_isopen()) \
       syslog((level), msg); \
    print_msg((level), msg)

/* Convenient logging. */
#define log_error(msg...) log_msg(LOG_ERR, msg)
#define log_warning(msg...) log_msg(LOG_WARNING, msg)
#define log_notice(msg...) log_msg(LOG_NOTICE, msg)
#define log_info(msg...) log_msg(LOG_INFO, msg)
#define log_debug(msg...) log_msg(LOG_DEBUG, msg)

#endif // __print_h__
