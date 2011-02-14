/*!
 * \file log.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Logging facility.
 *
 * \note Loglevel defined in syslog.h, may be redefined in other backend, but
 * keep naming. LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG
 *
 * In standard mode, only LOG_ERR and LOG_WARNING is displayed and logged.
 * Verbose mode enables LOG_NOTICE and LOG_INFO for additional information.
 *
 * \addtogroup logging
 * @{
 */
#ifndef _CUTEDNS_LOG_H_
#define _CUTEDNS_LOG_H_

/*
 */
#include <syslog.h>

/*! \brief Log facility types (4 bits). */
typedef enum {
	LOGT_SYSLOG = 0, /*!< Logging to syslog(3) facility. */
	LOGT_STDERR = 1, /*!< Print log messages to the stderr. */
	LOGT_STDOUT = 2, /*!< Print log messages to the stdout. */
	LOGT_FILE   = 3  /*!< Generic logging to (unbuffered) file on the disk. */
} logtype_t;

/*! \brief Log sources (3 bits). */
typedef enum {
	LOG_SERVER = 0, /*!< Server module. */
	LOG_ANSWER = 1, /*!< Query answering module. */
	LOG_ZONE   = 2, /*!< Zone manipulation module. */
	LOG_ANY    = 7  /*!< Any module. */
} logsrc_t;

/* Logging facility setup. */

/*!
 * \brief Setup logging facilities without config.
 *
 * \see syslog.h
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int log_init(int print_mask, int log_mask);

/*!
 * \brief Close and deinitialize log.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int log_close();

/*!
 * \brief Return positive number if open.
 *
 * \return 1 if open (boolean true)
 * \return 0 if closed (boolean false)
 */
int log_isopen();

/* Logging functions. */
int print_msg(int level, const char *msg, ...) __attribute__((format(printf, 2, 3)));

#define log_msg(level, msg...) \
	do { \
	if(log_isopen()) { \
		syslog((level), msg); \
	} \
	print_msg((level), msg); \
	} while (0)

/* Convenient logging. */
#define log_error(msg...)     log_msg(LOG_ERR, msg)
#define log_warning(msg...)   log_msg(LOG_WARNING, msg)
#define log_notice(msg...)    log_msg(LOG_NOTICE, msg)
#define log_info(msg...)      log_msg(LOG_INFO, msg)
#define log_debug(msg...)     log_msg(LOG_DEBUG, msg)

#endif /* _CUTEDNS_LOG_H_ */

/*! @} */
