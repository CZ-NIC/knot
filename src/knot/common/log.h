/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file log.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Logging facility.
 *
 * \note Loglevel defined in syslog.h, may be redefined in other backend, but
 * keep naming. LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG
 *
 * In standard mode, only LOG_CRIT, LOG_ERR and LOG_WARNING is logged.
 * Verbose mode enables LOG_NOTICE and LOG_INFO for additional information.
 *
 * \addtogroup logging
 * @{
 */

#pragma once

#include <syslog.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <assert.h>

#include "libknot/dname.h"
#include "knot/conf/conf.h"

/*! \brief Log facility types. */
typedef enum {
	LOGT_SYSLOG = 0, /*!< Logging to syslog(3) facility. */
	LOGT_STDERR = 1, /*!< Print log messages to the stderr. */
	LOGT_STDOUT = 2, /*!< Print log messages to the stdout. */
	LOGT_FILE   = 3  /*!< Generic logging to (unbuffered) file on the disk. */
} logtype_t;

/*! \brief Log sources width (bits). */
#define LOG_SRC_BITS 3

/*! \brief Log sources (max. LOG_SRC_BITS bits). */
typedef enum {
	LOG_SERVER = 0, /*!< Server module. */
	LOG_ZONE   = 1, /*!< Zone manipulation module. */
	LOG_ANY    = 7  /*!< Any module. */
} logsrc_t;

/*! \brief Logging format flags. */
typedef enum {
	LOG_FNO_TIMESTAMP = 1 << 0, /*!< Don't print timestamp prefix. */
	LOG_FNO_INFO      = 1 << 1  /*!< Don't print info level prefix. */
} logflag_t;

/*! \brief Format for timestamps in log files. */
#define KNOT_LOG_TIME_FORMAT "%Y-%m-%dT%H:%M:%S"

/*!
 * \brief Setup logging subsystem.
 *
 * \see syslog.h
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ENOMEM out of memory error.
 */
int log_init();

/*!
 * \brief Close and deinitialize log.
 */
void log_close();

/*!
 * \brief Return true if log is open.
 */
bool log_isopen();

/*!
 * \brief Set logging format flag.
 */
void log_flag_set(logflag_t flag);

/*!
 * \brief Return log levels for a given facility.
 *
 * \param facility Given log facility index.
 * \param src Given log source in the context of current facility.
 *
 * \retval Associated log level flags on success.
 * \retval 0 on error.
 */
uint8_t log_levels(int facility, logsrc_t src);

/*!
 * \brief Set log levels for given facility.
 *
 * \param facility Logging facility index (LOGT_SYSLOG...).
 * \param src Logging source (LOG_SERVER...LOG_ANY).
 * \param levels Bitmask of specified log levels.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters (facility out of range).
 */
int log_levels_set(int facility, logsrc_t src, uint8_t levels);

/*!
 * \brief Add log levels to a given facility.
 *
 * New levels are added on top of existing, the resulting
 * levels set is "old_levels OR new_levels".
 *
 * \param facility Logging facility index (LOGT_SYSLOG...).
 * \param src Logging source (LOG_SERVER...LOG_ANY).
 * \param levels Bitmask of specified log levels.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters (facility out of range).
 */
int log_levels_add(int facility, logsrc_t src, uint8_t levels);

/*!
 * \brief Log message into server category.
 *
 * Function follows printf() format.
 *
 * \param priority  Message error level.
 * \param fmt       Content of the logged message.
 *
 * \return Number of logged bytes, negative error.
 */
int log_msg(int priority, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/*!
 * \brief Log message into zone category.
 *
 * \see log_msg
 * \param zone  Zone name in wire format.
 */
int log_msg_zone(int priority, const knot_dname_t *zone, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/*!
 * \brief Log message into zone category.
 *
 * \see log_msg
 * \param zone  Zone name as an ASCII string.
 */
int log_msg_zone_str(int priority, const char *zone, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* Convenient logging. */

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
 * \param uid New owner id.
 * \param gid New group id.
 * \retval KNOT_EOK if success
 * \retval KNOT_ERROR on error
 */
int log_update_privileges(int uid, int gid);

/*!
 * \brief Setup logging facilities from config.
 *
 * \see syslog.h
 */
void log_reconfigure(conf_t *conf);

/*! @} */
