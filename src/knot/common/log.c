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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <urcu.h>

#ifdef ENABLE_SYSTEMD
#define SD_JOURNAL_SUPPRESS_LOCATION 1
#include <systemd/sd-journal.h>
#include <systemd/sd-daemon.h>
#endif

#include "knot/common/log.h"
#include "libknot/libknot.h"
#include "contrib/ucw/lists.h"

/*! Single log message buffer length (one line). */
#define LOG_BUFLEN	512
#define NULL_ZONE_STR	"?"

#ifdef ENABLE_SYSTEMD
int use_journal = 0;
#endif

/*! Log context. */
typedef struct {
	size_t facility_count; /*!< Log sink count. */
	int *facility;         /*!< Log sinks. */
	size_t file_count;     /*!< Open files count. */
	FILE **file;           /*!< Open files. */
	logflag_t flags;       /*!< Formatting flags. */
} log_t;

/*! Log singleton. */
log_t *s_log = NULL;

static bool log_isopen(void)
{
	return s_log != NULL;
}

static void sink_free(log_t *log)
{
	if (log == NULL) {
		return;
	}

	// Close open log files.
	for (int i = 0; i < log->file_count; ++i) {
		fclose(log->file[i]);
	}
	free(log->facility);
	free(log->file);
	free(log);
}

/*!
 * \brief Create logging facilities respecting their canonical order.
 *
 * Facilities ordering: Syslog, Stderr, Stdout, File0...
 */
static log_t *sink_setup(size_t file_count)
{
	log_t *log = malloc(sizeof(*log));
	if (log == NULL) {
		return NULL;
	}
	memset(log, 0, sizeof(*log));

	// Reserve space for facilities.
	log->facility_count = LOGT_FILE + file_count;
	log->facility = malloc(LOG_ANY * sizeof(int) * log->facility_count);
	if (!log->facility) {
		free(log);
		return NULL;
	}
	memset(log->facility, 0, LOG_ANY * sizeof(int) * log->facility_count);

	// Reserve space for log files.
	if (file_count > 0) {
		log->file = malloc(sizeof(FILE *) * file_count);
		if (!log->file) {
			free(log->facility);
			free(log);
			return NULL;
		}
		memset(log->file, 0, sizeof(FILE *) * file_count);
	}

	return log;
}

static void sink_publish(log_t *log)
{
	log_t **current_log = &s_log;
	log_t *old_log = rcu_xchg_pointer(current_log, log);
	synchronize_rcu();
	sink_free(old_log);
}

static int *src_levels(log_t *log, logfacility_t facility, logsrc_t src)
{
	assert(src < LOG_ANY);
	return &log->facility[LOG_ANY * facility + src];
}

static void sink_levels_set(log_t *log, logfacility_t facility, logsrc_t src, int levels)
{
	// Assign levels to the specified source.
	if (src != LOG_ANY) {
		*src_levels(log, facility, src) = levels;
	} else {
		// ANY ~ set levels to all sources.
		for (int i = 0; i < LOG_ANY; ++i) {
			*src_levels(log, facility, i) = levels;
		}
	}
}

static void sink_levels_add(log_t *log, logfacility_t facility, logsrc_t src, int levels)
{
	// Add levels to the specified source.
	if (src != LOG_ANY) {
		*src_levels(log, facility, src) |= levels;
	} else {
		// ANY ~ add levels to all sources.
		for (int i = 0; i < LOG_ANY; ++i) {
			*src_levels(log, facility, i) |= levels;
		}
	}
}

void log_init(void)
{
	// Setup initial state.
	int emask = LOG_MASK(LOG_CRIT) | LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING);
	int imask = LOG_MASK(LOG_NOTICE) | LOG_MASK(LOG_INFO);

	// Publish base log sink.
	log_t *log = sink_setup(0);
	if (log == NULL) {
		fprintf(stderr, "Failed to setup logging\n");
		return;
	}

#ifdef ENABLE_SYSTEMD
	// Should only use the journal if system was booted with systemd.
	use_journal = sd_booted();
#endif

	sink_levels_set(log, LOGT_SYSLOG, LOG_ANY, emask);
	sink_levels_set(log, LOGT_STDERR, LOG_ANY, emask);
	sink_levels_set(log, LOGT_STDOUT, LOG_ANY, imask);
	sink_publish(log);

	setlogmask(LOG_UPTO(LOG_DEBUG));
	openlog(PACKAGE_NAME, LOG_PID, LOG_DAEMON);
}

void log_close(void)
{
	sink_publish(NULL);

	fflush(stdout);
	fflush(stderr);

	closelog();
}

void log_flag_set(logflag_t flag)
{
	if (log_isopen()) {
		s_log->flags |= flag;
	}
}

void log_levels_set(logfacility_t facility, logsrc_t src, int levels)
{
	if (log_isopen()) {
		sink_levels_set(s_log, facility, src, levels);
	}
}

void log_levels_add(logfacility_t facility, logsrc_t src, int levels)
{
	if (log_isopen()) {
		sink_levels_add(s_log, facility, src, levels);
	}
}

static void emit_log_msg(int level, const char *zone, size_t zone_len, const char *msg)
{
	log_t *log = s_log;
	logsrc_t src = zone ? LOG_ZONE : LOG_SERVER;

	// Syslog facility.
	if (*src_levels(log, LOGT_SYSLOG, src) & LOG_MASK(level)) {
#ifdef ENABLE_SYSTEMD
		if (use_journal) {
			char *zone_fmt = zone ? "ZONE=%.*s" : NULL;
			sd_journal_send("PRIORITY=%d", level,
			                "MESSAGE=%s", msg,
			                zone_fmt, zone_len, zone,
			                NULL);
		} else
#endif
		{
			syslog(level, "%s", msg);
		}
	}

	// Prefix date and time.
	char tstr[LOG_BUFLEN] = { 0 };
	if (!(s_log->flags & LOG_FNO_TIMESTAMP)) {
		struct tm lt;
		struct timeval tv;
		gettimeofday(&tv, NULL);
		time_t sec = tv.tv_sec;
		if (localtime_r(&sec, &lt) != NULL) {
			strftime(tstr, sizeof(tstr), KNOT_LOG_TIME_FORMAT " ", &lt);
		}
	}

	// Other log facilities.
	for (int i = LOGT_STDERR; i < LOGT_FILE + log->file_count; ++i) {
		if (*src_levels(log, i, src) & LOG_MASK(level)) {
			FILE *stream;
			switch (i) {
			case LOGT_STDERR: stream = stderr; break;
			case LOGT_STDOUT: stream = stdout; break;
			default: stream = log->file[i - LOGT_FILE]; break;
			}

			// Print the message.
			fprintf(stream, "%s%s\n", tstr, msg);
			if (stream == stdout) {
				fflush(stream);
			}
		}
	}
}

static const char *level_prefix(int level)
{
	switch (level) {
	case LOG_DEBUG:   return "debug";
	case LOG_INFO:    return "info";
	case LOG_NOTICE:  return "notice";
	case LOG_WARNING: return "warning";
	case LOG_ERR:     return "error";
	case LOG_CRIT:    return "critical";
	default:          return NULL;
	};
}

static int log_msg_add(char **write, size_t *capacity, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int written = vsnprintf(*write, *capacity, fmt, args);
	va_end(args);

	if (written < 0 || written >= *capacity) {
		return KNOT_ESPACE;
	}

	*write += written;
	*capacity -= written;

	return KNOT_EOK;
}

static void log_msg_text(int level, const char *zone, const char *fmt, va_list args)
{
	if (!log_isopen()) {
		return;
	}

	// Buffer for log message.
	char buff[LOG_BUFLEN];
	char *write = buff;
	size_t capacity = sizeof(buff);

	rcu_read_lock();

	// Prefix error level.
	if (level != LOG_INFO || !(s_log->flags & LOG_FNO_INFO)) {
		const char *prefix = level_prefix(level);
		int ret = log_msg_add(&write, &capacity, "%s: ", prefix);
		if (ret != KNOT_EOK) {
			rcu_read_unlock();
			return;
		}
	}

	// Prefix zone name.
	size_t zone_len = 0;
	if (zone != NULL) {
		zone_len = strlen(zone);

		int ret = log_msg_add(&write, &capacity, "[%.*s] ", zone_len, zone);
		if (ret != KNOT_EOK) {
			rcu_read_unlock();
			return;
		}
	}

	// Compile log message.
	int ret = vsnprintf(write, capacity, fmt, args);
	if (ret >= 0) {
		// Send to logging facilities.
		emit_log_msg(level, zone, zone_len, buff);
	}

	rcu_read_unlock();
}

void log_msg(int priority, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	log_msg_text(priority, NULL, fmt, args);
	va_end(args);
}

void log_msg_zone(int priority, const knot_dname_t *zone, const char *fmt, ...)
{
	char buff[KNOT_DNAME_TXT_MAXLEN + 1];
	char *zone_str = knot_dname_to_str(buff, zone, sizeof(buff));

	va_list args;
	va_start(args, fmt);
	log_msg_text(priority, zone_str ? zone_str : NULL_ZONE_STR, fmt, args);
	va_end(args);
}

void log_msg_zone_str(int priority, const char *zone, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	log_msg_text(priority, zone ? zone : NULL_ZONE_STR, fmt, args);
	va_end(args);
}

int log_update_privileges(int uid, int gid)
{
	if (!log_isopen()) {
		return KNOT_EOK;
	}

	for (int i = 0; i < s_log->file_count; ++i) {
		if (fchown(fileno(s_log->file[i]), uid, gid) < 0) {
			return knot_map_errno();
		}
	}

	return KNOT_EOK;
}

static logfacility_t get_logtype(const char *logname)
{
	assert(logname);

	if (strcasecmp(logname, "syslog") == 0) {
		return LOGT_SYSLOG;
	} else if (strcasecmp(logname, "stderr") == 0) {
		return LOGT_STDERR;
	} else if (strcasecmp(logname, "stdout") == 0) {
		return LOGT_STDOUT;
	} else {
		return LOGT_FILE;
	}
}

static int log_open_file(log_t *log, const char *filename)
{
	assert(LOGT_FILE + log->file_count < log->facility_count);

	// Open the file.
	log->file[log->file_count] = fopen(filename, "a");
	if (log->file[log->file_count] == NULL) {
		return knot_map_errno();
	}

	// Disable buffering.
	setvbuf(log->file[log->file_count], NULL, _IONBF, 0);

	return LOGT_FILE + log->file_count++;
}

void log_reconfigure(conf_t *conf)
{
	// Use defaults if no 'log' section is configured.
	if (conf_id_count(conf, C_LOG) == 0) {
		log_close();
		log_init();
		return;
	}

	// Find maximum log facility id.
	unsigned files = 0;
	for (conf_iter_t iter = conf_iter(conf, C_LOG); iter.code == KNOT_EOK;
	     conf_iter_next(conf, &iter)) {
		conf_val_t id = conf_iter_id(conf, &iter);
		if (get_logtype(conf_str(&id)) == LOGT_FILE) {
			++files;
		}
	}

	// Initialize logsystem.
	log_t *log = sink_setup(files);
	if (log == NULL) {
		fprintf(stderr, "Failed to setup logging\n");
		return;
	}

	// Setup logs.
	for (conf_iter_t iter = conf_iter(conf, C_LOG); iter.code == KNOT_EOK;
	     conf_iter_next(conf, &iter)) {
		conf_val_t id = conf_iter_id(conf, &iter);
		const char *logname = conf_str(&id);

		// Get facility.
		int facility = get_logtype(logname);
		if (facility == LOGT_FILE) {
			facility = log_open_file(log, logname);
			if (facility < 0) {
				log_error("failed to open log, file '%s' (%s)",
				          logname, knot_strerror(facility));
				continue;
			}
		}

		conf_val_t levels_val;
		unsigned levels;

		// Set SERVER logging.
		levels_val = conf_id_get(conf, C_LOG, C_SERVER, &id);
		levels = conf_opt(&levels_val);
		sink_levels_add(log, facility, LOG_SERVER, levels);

		// Set ZONE logging.
		levels_val = conf_id_get(conf, C_LOG, C_ZONE, &id);
		levels = conf_opt(&levels_val);
		sink_levels_add(log, facility, LOG_ZONE, levels);

		// Set ANY logging.
		levels_val = conf_id_get(conf, C_LOG, C_ANY, &id);
		levels = conf_opt(&levels_val);
		sink_levels_add(log, facility, LOG_ANY, levels);
	}

	sink_publish(log);
}
