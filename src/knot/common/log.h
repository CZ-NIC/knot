/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file
 *
 * \brief Logging facility.
 *
 * Supported log levels/priorities:
 * LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, and LOG_DEBUG.
 *
 * \see syslog.h
 *
 * \addtogroup logging
 * @{
 */

#pragma once

#include <assert.h>
#include <syslog.h>
#include <stdint.h>
#include <stdbool.h>

#include "libknot/dname.h"
#include "knot/conf/conf.h"

/*! \brief Format for timestamps in log files. */
#define KNOT_LOG_TIME_FORMAT "%Y-%m-%dT%H:%M:%S"

/*! \brief Logging facility types. */
typedef enum {
	LOGT_SYSLOG = 0, /*!< Logging to syslog(3) facility. */
	LOGT_STDERR = 1, /*!< Print log messages to the stderr. */
	LOGT_STDOUT = 2, /*!< Print log messages to the stdout. */
	LOGT_FILE   = 3  /*!< Generic logging to (unbuffered) file on the disk. */
} logfacility_t;

/*! \brief Logging sources. */
typedef enum {
	LOG_SERVER = 0, /*!< Server module. */
	LOG_ZONE   = 1, /*!< Zone manipulation module. */
	LOG_ANY    = 2  /*!< Any module. */
} logsrc_t;

/*! \brief Logging format flags. */
typedef enum {
	LOG_FNO_TIMESTAMP = 1 << 0, /*!< Don't print timestamp prefix. */
	LOG_FNO_INFO      = 1 << 1  /*!< Don't print info level prefix. */
} logflag_t;

/*!
 * \brief Setup logging subsystem.
 */
void log_init(void);

/*!
 * \brief Close and deinitialize log.
 */
void log_close(void);

/*!
 * \brief Set logging format flag.
 */
void log_flag_set(logflag_t flag);

/*!
 * \brief Set log levels for given facility.
 *
 * \param facility  Logging facility index (LOGT_SYSLOG...).
 * \param src       Logging source (LOG_SERVER...LOG_ANY).
 * \param levels    Bitmask of specified log levels.
 */
void log_levels_set(logfacility_t facility, logsrc_t src, int levels);

/*!
 * \brief Add log levels to a given facility.
 *
 * New levels are added on top of existing, the resulting levels set is
 * "old_levels OR new_levels".
 *
 * \param facility  Logging facility index (LOGT_SYSLOG...).
 * \param src       Logging source (LOG_SERVER...LOG_ANY).
 * \param levels    Bitmask of specified log levels.
 */
void log_levels_add(logfacility_t facility, logsrc_t src, int levels);

/*!
 * \brief Log message into server category.
 *
 * Function follows printf() format.
 *
 * \param priority  Message priority.
 * \param fmt       Content of the logged message.
 */
void log_msg(int priority, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/*!
 * \brief Log message into zone category.
 *
 * \see log_msg
 *
 * \param zone  Zone name in wire format.
 */
void log_msg_zone(int priority, const knot_dname_t *zone, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

/*!
 * \brief Log message into zone category.
 *
 * \see log_msg
 *
 * \param zone  Zone name as an ASCII string.
 */
void log_msg_zone_str(int priority, const char *zone, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

/*!
 * \brief Convenient logging macros.
 */
#define log_fatal(msg, ...)   log_msg(LOG_CRIT,    msg, ##__VA_ARGS__)
#define log_error(msg, ...)   log_msg(LOG_ERR,     msg, ##__VA_ARGS__)
#define log_warning(msg, ...) log_msg(LOG_WARNING, msg, ##__VA_ARGS__)
#define log_notice(msg, ...)  log_msg(LOG_NOTICE,  msg, ##__VA_ARGS__)
#define log_info(msg, ...)    log_msg(LOG_INFO,    msg, ##__VA_ARGS__)
#define log_debug(msg, ...)   log_msg(LOG_DEBUG,   msg, ##__VA_ARGS__)

#define log_zone_fatal(zone, msg, ...)   log_msg_zone(LOG_CRIT,    zone, msg, ##__VA_ARGS__)
#define log_zone_error(zone, msg, ...)   log_msg_zone(LOG_ERR,     zone, msg, ##__VA_ARGS__)
#define log_zone_warning(zone, msg, ...) log_msg_zone(LOG_WARNING, zone, msg, ##__VA_ARGS__)
#define log_zone_notice(zone, msg, ...)  log_msg_zone(LOG_NOTICE,  zone, msg, ##__VA_ARGS__)
#define log_zone_info(zone, msg, ...)    log_msg_zone(LOG_INFO,    zone, msg, ##__VA_ARGS__)
#define log_zone_debug(zone, msg, ...)   log_msg_zone(LOG_DEBUG,   zone, msg, ##__VA_ARGS__)

#define log_zone_str_fatal(zone, msg, ...)   log_msg_zone_str(LOG_CRIT,    zone, msg, ##__VA_ARGS__)
#define log_zone_str_error(zone, msg, ...)   log_msg_zone_str(LOG_ERR,     zone, msg, ##__VA_ARGS__)
#define log_zone_str_warning(zone, msg, ...) log_msg_zone_str(LOG_WARNING, zone, msg, ##__VA_ARGS__)
#define log_zone_str_notice(zone, msg, ...)  log_msg_zone_str(LOG_NOTICE,  zone, msg, ##__VA_ARGS__)
#define log_zone_str_info(zone, msg, ...)    log_msg_zone_str(LOG_INFO,    zone, msg, ##__VA_ARGS__)
#define log_zone_str_debug(zone, msg, ...)   log_msg_zone_str(LOG_DEBUG,   zone, msg, ##__VA_ARGS__)

/*!
 * \brief Update open files ownership.
 *
 * \param uid  New owner id.
 * \param gid  New group id.
 *
 * \return Error code, KNOT_EOK if success.
 */
int log_update_privileges(int uid, int gid);

/*!
 * \brief Setup logging facilities from config.
 */
void log_reconfigure(conf_t *conf);

/*! @} */
