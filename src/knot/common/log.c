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
#include "contrib/macros.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/ucw/lists.h"

/* Single log message buffer length (one line). */
#define LOG_BUFLEN 512

#define LOG_NULL_ZONE_STRING "?"

/*! Log source table. */
struct log_sink
{
	uint8_t *facility;     /* Log sinks. */
	size_t facility_count; /* Sink count. */
	FILE **file;           /* Open files. */
	ssize_t file_count;    /* Nr of open files. */
	logflag_t flags;       /* Formatting flags. */
};

/*! Log sink singleton. */
struct log_sink *s_log = NULL;

#ifdef ENABLE_SYSTEMD
int use_journal = 0;
#endif

#define facility_at(s, i) (s->facility + ((i) << LOG_SRC_BITS))
#define facility_next(f) (f) += (1 << LOG_SRC_BITS)
#define facility_levels(f, i) *((f) + (i))

/*! \brief Close open files and free given sink. */
static void sink_free(struct log_sink *log)
{
	if (log == NULL) {
		return;
	}

	/* Close open logfiles. */
	for (int i = 0; i < log->file_count; ++i) {
		fclose(log->file[i]);
	}
	free(log->facility);
	free(log->file);
	free(log);
}

/*!
 * \brief Create logging facilities respecting their
 *        canonical order.
 *
 * Facilities ordering: Syslog, Stderr, Stdout, File0...
 */
static struct log_sink *sink_setup(unsigned logfiles)
{
	struct log_sink *log = malloc(sizeof(struct log_sink));
	if (log == NULL) {
		return NULL;
	}

	/* Ensure minimum facilities count. */
	int facilities = LOGT_FILE + logfiles;

	/* Reserve space for facilities. */
	memset(log, 0, sizeof(struct log_sink));
	log->facility_count = facilities << LOG_SRC_BITS;
	log->facility = malloc(log->facility_count);
	if (!log->facility) {
		free(log);
		return NULL;
	}
	memset(log->facility, 0, log->facility_count);

	/* Reserve space for logfiles. */
	if (logfiles > 0) {
		log->file = malloc(sizeof(FILE*) * logfiles);
		if (!log->file) {
			free(log->facility);
			free(log);
			return NULL;
		}
		memset(log->file, 0, sizeof(FILE*) * logfiles);
	}

	return log;
}

/*! \brief Publish new log sink and free the replaced. */
static void sink_publish(struct log_sink *log)
{
	struct log_sink **current_log = &s_log;
	struct log_sink *old_log = rcu_xchg_pointer(current_log, log);
	synchronize_rcu();
	sink_free(old_log);
}

static uint8_t sink_levels(struct log_sink *log, int facility, logsrc_t src)
{
	assert(log);

	// Check facility
	if (unlikely(log->facility_count == 0 || facility >= log->facility_count)) {
		return 0;
	}

	return *(log->facility + (facility << LOG_SRC_BITS) + src);
}

static int sink_levels_set(struct log_sink *log, int facility, logsrc_t src, uint8_t levels)
{
	// Check facility
	if (unlikely(log->facility_count == 0 || facility >= log->facility_count)) {
		return KNOT_EINVAL;
	}

	// Get facility pointer from offset
	uint8_t *lp = log->facility + (facility << LOG_SRC_BITS);

	// Assign level if not multimask
	if (src != LOG_ANY) {
		*(lp + src) = levels;
	} else {
		// Any == set to all sources
		for (int i = 0; i <= LOG_ANY; ++i) {
			*(lp + i) = levels;
		}
	}

	return KNOT_EOK;
}

static int sink_levels_add(struct log_sink *log, int facility, logsrc_t src, uint8_t levels)
{
	uint8_t new_levels = sink_levels(log, facility, src) | levels;
	return sink_levels_set(log, facility, src, new_levels);
}

int log_init()
{
	/* Setup initial state. */
	int ret = KNOT_EOK;
	int emask = LOG_MASK(LOG_CRIT) | LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING);
	int imask = LOG_MASK(LOG_NOTICE) | LOG_MASK(LOG_INFO);

	/* Publish base log sink. */
	struct log_sink *log = sink_setup(0);
	if (log == NULL) {
		return KNOT_EINVAL;
	}

#ifdef ENABLE_SYSTEMD
	/* Should only use the journal if system was booted with systemd */
	use_journal = sd_booted();
#endif
	sink_levels_set(log, LOGT_SYSLOG, LOG_ANY, emask);
	sink_levels_set(log, LOGT_STDERR, LOG_ANY, emask);
	sink_levels_set(log, LOGT_STDOUT, LOG_ANY, imask);
	sink_publish(log);

	setlogmask(LOG_UPTO(LOG_DEBUG));
	openlog(PACKAGE_NAME, LOG_PID, LOG_DAEMON);
	return ret;
}

void log_close()
{
	sink_publish(NULL);

	fflush(stdout);
	fflush(stderr);

	closelog();
}

bool log_isopen()
{
	return s_log != NULL;
}

void log_flag_set(logflag_t flag)
{
	s_log->flags |= flag;
}

/*! \brief Open file as a logging facility. */
static int log_open_file(struct log_sink *log, const char* filename)
{
	// Check facility
	if (unlikely(log->facility_count  == 0 ||
	                  LOGT_FILE + log->file_count >= log->facility_count)) {
		return KNOT_ERROR;
	}

	// Open file
	log->file[log->file_count] = fopen(filename, "a");
	if (!log->file[log->file_count]) {
		return KNOT_EINVAL;
	}

	// Disable buffering
	setvbuf(log->file[log->file_count], (char *)0, _IONBF, 0);

	return LOGT_FILE + log->file_count++;
}

uint8_t log_levels(int facility, logsrc_t src)
{
	return sink_levels(s_log, facility, src);
}

int log_levels_set(int facility, logsrc_t src, uint8_t levels)
{
	return sink_levels_set(s_log, facility, src, levels);
}

int log_levels_add(int facility, logsrc_t src, uint8_t levels)
{
	return sink_levels_add(s_log, facility, src, levels);
}

static int emit_log_msg(int level, const char *zone, size_t zone_len, const char *msg)
{
	struct log_sink *log = s_log;
	if(!log_isopen()) {
		return KNOT_ERROR;
	}

	int ret = 0;
	uint8_t *f = facility_at(log, LOGT_SYSLOG);
	logsrc_t src = zone ? LOG_ZONE : LOG_SERVER;

	// Syslog
	if (facility_levels(f, src) & LOG_MASK(level)) {
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
		ret = 1; // To prevent considering the message as ignored.
	}

	// Convert level to mask
	level = LOG_MASK(level);

	/* Prefix date and time. */
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

	// Log streams
	for (int i = LOGT_STDERR; i < LOGT_FILE + log->file_count; ++i) {

		// Check facility levels mask
		f = facility_at(log, i);
		if (facility_levels(f, src) & level) {

			// Select stream
			FILE *stream;
			switch(i) {
			case LOGT_STDERR: stream = stderr; break;
			case LOGT_STDOUT: stream = stdout; break;
			default: stream = log->file[i - LOGT_FILE]; break;
			}

			// Print
			ret = fprintf(stream, "%s%s\n", tstr, msg);
			if (stream == stdout) {
				fflush(stream);
			}
		}
	}

	if (ret < 0) {
		return KNOT_EINVAL;
	}

	return ret;
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
	default:
		return NULL;
	};
}

static int log_msg_add(char **write, size_t *capacity, const char *fmt, ...)
{
	assert(*write);
	assert(capacity);
	assert(fmt);

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

static int log_msg_text(int level, const char *zone, const char *fmt, va_list args)
{
	int ret;

	/* Buffer for log message. */
	char sbuf[LOG_BUFLEN];
	char *write = sbuf;
	size_t capacity = sizeof(sbuf) - 1;

	rcu_read_lock();

	/* Prefix error level. */
	if (level != LOG_INFO || !log_isopen() || !(s_log->flags & LOG_FNO_INFO)) {
		const char *prefix = level_prefix(level);
		ret = log_msg_add(&write, &capacity, "%s: ", prefix);
		if (ret != KNOT_EOK) {
			rcu_read_unlock();
			return ret;
		}
	}

	/* Prefix zone name. */
	size_t zone_len = 0;
	if (zone) {
		/* Strip terminating dot (unless root zone). */
		zone_len = strlen(zone);
		if (zone_len > 1 && zone[zone_len - 1] == '.') {
			zone_len -= 1;
		}

		ret = log_msg_add(&write, &capacity, "[%.*s] ", zone_len, zone);
		if (ret != KNOT_EOK) {
			rcu_read_unlock();
			return ret;
		}
	}

	/* Compile log message. */
	ret = vsnprintf(write, capacity, fmt, args);

	/* Send to logging facilities. */
	if (ret >= 0) {
		ret = emit_log_msg(level, zone, zone_len, sbuf);
	}

	rcu_read_unlock();

	return ret;
}

int log_msg(int priority, const char *fmt, ...)
{
	if (!fmt) {
		return KNOT_EINVAL;
	}

	va_list args;
	va_start(args, fmt);
	int result = log_msg_text(priority, NULL, fmt, args);
	va_end(args);

	return result;
}

int log_msg_zone(int priority, const knot_dname_t *zone, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char *zone_str = knot_dname_to_str_alloc(zone);
	int result = log_msg_text(priority,
				  zone_str ? zone_str : LOG_NULL_ZONE_STRING,
				  fmt, args);
	free(zone_str);
	va_end(args);

	return result;
}

int log_msg_zone_str(int priority, const char *zone, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int result = log_msg_text(priority,
				  zone ? zone : LOG_NULL_ZONE_STRING,
				  fmt, args);
	va_end(args);

	return result;
}

int log_update_privileges(int uid, int gid)
{
	for (unsigned i = 0; i < s_log->file_count; ++i) {
		if (fchown(fileno(s_log->file[i]), uid, gid) < 0) {
			return KNOT_ERROR;
		}

	}
	return KNOT_EOK;
}

static logtype_t get_logtype(const char *logname)
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

int log_reconfigure(conf_t *conf, void *data)
{
	// Data not used
	UNUSED(data);

	// Use defaults if no 'log' section is configured.
	if (conf_id_count(conf, C_LOG) == 0) {
		log_close();
		log_init();
		return KNOT_EOK;
	}

	// Find maximum log facility id
	unsigned files = 0;
	for (conf_iter_t iter = conf_iter(conf, C_LOG); iter.code == KNOT_EOK;
	     conf_iter_next(conf, &iter)) {
		conf_val_t id = conf_iter_id(conf, &iter);
		if (get_logtype(conf_str(&id)) == LOGT_FILE) {
			++files;
		}
	}

	// Initialize logsystem
	struct log_sink *log = sink_setup(files);
	if (log == NULL) {
		return KNOT_ENOMEM;
	}

	// Setup logs
	for (conf_iter_t iter = conf_iter(conf, C_LOG); iter.code == KNOT_EOK;
	     conf_iter_next(conf, &iter)) {
		conf_val_t id = conf_iter_id(conf, &iter);
		const char *logname = conf_str(&id);

		// Get facility.
		int facility = get_logtype(logname);
		if (facility == LOGT_FILE) {
			facility = log_open_file(log, logname);
			if (facility < 0) {
				log_error("failed to open log, file '%s'",
				          logname);
				continue;
			}
		}

		conf_val_t level_val;
		unsigned level;

		// Set SERVER logging.
		level_val = conf_id_get(conf, C_LOG, C_SERVER, &id);
		level = conf_opt(&level_val);
		sink_levels_add(log, facility, LOG_SERVER, level);

		// Set ZONE logging.
		level_val = conf_id_get(conf, C_LOG, C_ZONE, &id);
		level = conf_opt(&level_val);
		sink_levels_add(log, facility, LOG_ZONE, level);

		// Set ANY logging.
		level_val = conf_id_get(conf, C_LOG, C_ANY, &id);
		level = conf_opt(&level_val);
		sink_levels_add(log, facility, LOG_ANY, level);
	}

	sink_publish(log);

	return KNOT_EOK;
}
