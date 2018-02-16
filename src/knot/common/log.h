/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Logging facility.
 *
 * Supported log levels/priorities:
 * LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, and LOG_DEBUG.
 *
 * \see syslog.h
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

/*! \brief Logging targets. */
typedef enum {
	LOG_TARGET_SYSLOG = 0, /*!< System log. */
	LOG_TARGET_STDERR = 1, /*!< Standard error stream. */
	LOG_TARGET_STDOUT = 2, /*!< Standard output stream. */
	LOG_TARGET_FILE   = 3  /*!< Generic logging to a file (unbuffered). */
} log_target_t;

/*! \brief Logging sources. */
typedef enum {
	LOG_SOURCE_SERVER  = 0, /*!< Server module. */
	LOG_SOURCE_CONTROL = 1, /*!< Server control module. */
	LOG_SOURCE_ZONE    = 2, /*!< Zone manipulation module. */
	LOG_SOURCE_ANY     = 3  /*!< Any module. */
} log_source_t;

/*! \brief Logging format flags. */
typedef enum {
	LOG_FLAG_NOTIMESTAMP = 1 << 0, /*!< Don't print timestamp prefix. */
	LOG_FLAG_NOINFO      = 1 << 1  /*!< Don't print info level prefix. */
} log_flag_t;

/*! \brief Events to be logged structuredly into systemd. */
typedef enum {
	LOG_EVENT_DNSSEC_PUBLISH = 0,
	LOG_EVENT_DNSSEC_REMOVE  = 1,
	LOG_EVENT_DNSSEC_SUBMIT  = 2,
	LOG_EVENT_DNSSEC_ACTIVE  = 3,
} log_structured_event_t;

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
void log_flag_set(log_flag_t flag);

/*!
 * \brief Set log levels for given target.
 *
 * \param target  Logging target index (LOG_TARGET_SYSLOG...).
 * \param src     Logging source (LOG_SOURCE_SERVER...LOG_SOURCE_ANY).
 * \param levels  Bitmask of specified log levels.
 */
void log_levels_set(log_target_t target, log_source_t src, int levels);

/*!
 * \brief Add log levels to a given target.
 *
 * New levels are added on top of existing, the resulting levels set is
 * "old_levels OR new_levels".
 *
 * \param target  Logging target index (LOG_TARGET_SYSLOG...).
 * \param src     Logging source (LOG_SOURCE_SERVER...LOG_SOURCE_ANY).
 * \param levels  Bitmask of specified log levels.
 */
void log_levels_add(log_target_t target, log_source_t src, int levels);

/*!
 * \brief Log message into server category.
 *
 * Function follows printf() format.
 *
 * \note LOG_SOURCE_ANY is not a valid value for the src parameter.
 *
 * \param priority  Message priority.
 * \param src       Message source (LOG_SOURCE_SERVER...LOG_SOURCE_ZONE).
 * \param fmt       Content of the logged message.
 */
void log_fmt(int priority, log_source_t src, const char *fmt, ...)
__attribute__((format(printf, 3, 4)));

/*!
 * \brief Log message into zone category.
 *
 * \see log_fmt
 *
 * \param priority  Message priority.
 * \param src       Message source (LOG_SOURCE_SERVER...LOG_SOURCE_ZONE).
 * \param zone      Zone name in wire format.
 * \param fmt       Content of the logged message.
 */
void log_fmt_zone(int priority, log_source_t src, const knot_dname_t *zone, const char *fmt, ...)
__attribute__((format(printf, 4, 5)));

/*!
 * \brief Log message into zone category.
 *
 * \see log_fmt
 *
 * \param priority  Message priority.
 * \param src       Message source (LOG_SOURCE_SERVER...LOG_SOURCE_ZONE).
 * \param zone      Zone name as an ASCII string.
 * \param fmt       Content of the logged message.
 */
void log_fmt_zone_str(int priority, log_source_t src, const char *zone, const char *fmt, ...)
__attribute__((format(printf, 4, 5)));

/*!
 * \brief Convenient logging macros.
 */
#define log_fatal(msg, ...)   log_fmt(LOG_CRIT,    LOG_SOURCE_SERVER, msg, ##__VA_ARGS__)
#define log_error(msg, ...)   log_fmt(LOG_ERR,     LOG_SOURCE_SERVER, msg, ##__VA_ARGS__)
#define log_warning(msg, ...) log_fmt(LOG_WARNING, LOG_SOURCE_SERVER, msg, ##__VA_ARGS__)
#define log_notice(msg, ...)  log_fmt(LOG_NOTICE,  LOG_SOURCE_SERVER, msg, ##__VA_ARGS__)
#define log_info(msg, ...)    log_fmt(LOG_INFO,    LOG_SOURCE_SERVER, msg, ##__VA_ARGS__)
#define log_debug(msg, ...)   log_fmt(LOG_DEBUG,   LOG_SOURCE_SERVER, msg, ##__VA_ARGS__)

#define log_ctl_fatal(msg, ...)   log_fmt(LOG_CRIT,    LOG_SOURCE_CONTROL, msg, ##__VA_ARGS__)
#define log_ctl_error(msg, ...)   log_fmt(LOG_ERR,     LOG_SOURCE_CONTROL, msg, ##__VA_ARGS__)
#define log_ctl_warning(msg, ...) log_fmt(LOG_WARNING, LOG_SOURCE_CONTROL, msg, ##__VA_ARGS__)
#define log_ctl_notice(msg, ...)  log_fmt(LOG_NOTICE,  LOG_SOURCE_CONTROL, msg, ##__VA_ARGS__)
#define log_ctl_info(msg, ...)    log_fmt(LOG_INFO,    LOG_SOURCE_CONTROL, msg, ##__VA_ARGS__)
#define log_ctl_debug(msg, ...)   log_fmt(LOG_DEBUG,   LOG_SOURCE_CONTROL, msg, ##__VA_ARGS__)

#define log_ctl_zone_str_error(zone, msg, ...) log_fmt_zone_str(LOG_ERR,   LOG_SOURCE_CONTROL, zone, msg, ##__VA_ARGS__)
#define log_ctl_zone_str_info(zone, msg, ...)  log_fmt_zone_str(LOG_INFO,  LOG_SOURCE_CONTROL, zone, msg, ##__VA_ARGS__)
#define log_ctl_zone_str_debug(zone, msg, ...) log_fmt_zone_str(LOG_DEBUG, LOG_SOURCE_CONTROL, zone, msg, ##__VA_ARGS__)

#define log_zone_fatal(zone, msg, ...)   log_fmt_zone(LOG_CRIT,    LOG_SOURCE_ZONE, zone, msg, ##__VA_ARGS__)
#define log_zone_error(zone, msg, ...)   log_fmt_zone(LOG_ERR,     LOG_SOURCE_ZONE, zone, msg, ##__VA_ARGS__)
#define log_zone_warning(zone, msg, ...) log_fmt_zone(LOG_WARNING, LOG_SOURCE_ZONE, zone, msg, ##__VA_ARGS__)
#define log_zone_notice(zone, msg, ...)  log_fmt_zone(LOG_NOTICE,  LOG_SOURCE_ZONE, zone, msg, ##__VA_ARGS__)
#define log_zone_info(zone, msg, ...)    log_fmt_zone(LOG_INFO,    LOG_SOURCE_ZONE, zone, msg, ##__VA_ARGS__)
#define log_zone_debug(zone, msg, ...)   log_fmt_zone(LOG_DEBUG,   LOG_SOURCE_ZONE, zone, msg, ##__VA_ARGS__)

#define log_zone_str_fatal(zone, msg, ...)   log_fmt_zone_str(LOG_CRIT,    LOG_SOURCE_ZONE, zone, msg, ##__VA_ARGS__)
#define log_zone_str_error(zone, msg, ...)   log_fmt_zone_str(LOG_ERR,     LOG_SOURCE_ZONE, zone, msg, ##__VA_ARGS__)
#define log_zone_str_warning(zone, msg, ...) log_fmt_zone_str(LOG_WARNING, LOG_SOURCE_ZONE, zone, msg, ##__VA_ARGS__)
#define log_zone_str_notice(zone, msg, ...)  log_fmt_zone_str(LOG_NOTICE,  LOG_SOURCE_ZONE, zone, msg, ##__VA_ARGS__)
#define log_zone_str_info(zone, msg, ...)    log_fmt_zone_str(LOG_INFO,    LOG_SOURCE_ZONE, zone, msg, ##__VA_ARGS__)
#define log_zone_str_debug(zone, msg, ...)   log_fmt_zone_str(LOG_DEBUG,   LOG_SOURCE_ZONE, zone, msg, ##__VA_ARGS__)

/*!
 * \brief Special structured logging into systemd for specific actions.
 *
 * \param zone   Zone name.
 * \param event  Type of the event to be logged.
 * \param param  Additional information in the format "<NAME>=%s", or NULL.
 * \param value  Value for the parameter.
 */
void log_structured(const knot_dname_t *zone, log_structured_event_t event,
                    const char *param, const char *value);

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
