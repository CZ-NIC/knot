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
 * keep naming. LOG_FATAL, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG
 *
 * In standard mode, only LOG_FATAL, LOG_ERR and LOG_WARNING is logged.
 * Verbose mode enables LOG_NOTICE and LOG_INFO for additional information.
 *
 * \addtogroup logging
 * @{
 */

#ifndef _KNOTD_LOG_H_
#define _KNOTD_LOG_H_

/*
 */
#include <syslog.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

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
	LOG_ANSWER = 1, /*!< Query answering module. */
	LOG_ZONE   = 2, /*!< Zone manipulation module. */
	LOG_ANY    = 7  /*!< Any module. */
} logsrc_t;

/*! \brief Severity mapping. */
#define LOG_FATAL LOG_CRIT /*!< Fatal errors cannot be masked. */

/* Logging facility setup. */

/*!
 * \brief Create logging facilities respecting their
 *        canonical order.
 *
 * Facilities ordering: Syslog, Stderr, Stdout, File0...
 * \see logtype_t
 *
 * \param logfiles Number of extra logfiles.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid number of logfiles (negative).
 */
int log_setup(int logfiles);

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
 * \brief Truncate current log setup.
 */
void log_truncate();

/*!
 * \brief Return positive number if open.
 *
 * \return 1 if open (boolean true)
 * \return 0 if closed (boolean false)
 */
int log_isopen();

/*!
 * \brief Open file as a logging facility.
 *
 * \param filename File path.
 *
 * \retval associated facility index on success.
 * \retval KNOT_EINVAL filename cannot be opened for writing.
 * \retval KNOT_ERROR unspecified error.
 */
int log_open_file(const char* filename);

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
 * \brief Log message.
 *
 * Function follows printf() format.
 *
 * \param src Origin of the message.
 * \param level Message error level.
 * \param msg Content of the logged message.
 *
 * \retval Number of logged bytes on success.
 * \retval 0 When the message is ignored.
 * \retval KNOT_EINVAL invalid parameters.
 * \retval KNOT_ERROR unspecified error.
 */
int log_msg(logsrc_t src, int level, const char *msg, ...)
    __attribute__((format(printf, 3, 4)));

/*!
 * \brief Log message for stdarg.
 *
 * \see log_msg
 */
int log_vmsg(logsrc_t src, int level, const char *msg, va_list ap);

void hex_log(int source, const char *data, int length);

/* Convenient logging. */
#define log_server_fatal(msg...)     log_msg(LOG_SERVER, LOG_FATAL, msg)
#define log_server_error(msg...)     log_msg(LOG_SERVER, LOG_ERR, msg)
#define log_server_warning(msg...)   log_msg(LOG_SERVER, LOG_WARNING, msg)
#define log_server_notice(msg...)    log_msg(LOG_SERVER, LOG_NOTICE, msg)
#define log_server_info(msg...)      log_msg(LOG_SERVER, LOG_INFO, msg)
#define log_server_debug(msg...)     log_msg(LOG_SERVER, LOG_DEBUG, msg)

#define log_answer_fatal(msg...)     log_msg(LOG_ANSWER, LOG_FATAL, msg)
#define log_answer_error(msg...)     log_msg(LOG_ANSWER, LOG_ERR, msg)
#define log_answer_warning(msg...)   log_msg(LOG_ANSWER, LOG_WARNING, msg)
#define log_answer_notice(msg...)    log_msg(LOG_ANSWER, LOG_NOTICE, msg)
#define log_answer_info(msg...)      log_msg(LOG_ANSWER, LOG_INFO, msg)
#define log_answer_debug(msg...)     log_msg(LOG_ANSWER, LOG_DEBUG, msg)

#define log_zone_fatal(msg...)       log_msg(LOG_ZONE, LOG_FATAL, msg)
#define log_zone_error(msg...)       log_msg(LOG_ZONE, LOG_ERR, msg)
#define log_zone_warning(msg...)     log_msg(LOG_ZONE, LOG_WARNING, msg)
#define log_zone_notice(msg...)      log_msg(LOG_ZONE, LOG_NOTICE, msg)
#define log_zone_info(msg...)        log_msg(LOG_ZONE, LOG_INFO, msg)
#define log_zone_debug(msg...)       log_msg(LOG_ZONE, LOG_DEBUG, msg)

#endif /* _KNOTD_LOG_H_ */

/*! @} */
