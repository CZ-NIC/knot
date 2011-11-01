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

#include <config.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "knot/common.h"
#include "knot/other/error.h"
#include "knot/other/log.h"
#include "common/lists.h"
#include "knot/conf/conf.h"

/*! Log source table. */
static uint8_t *LOG_FCL = 0;
static volatile size_t LOG_FCL_SIZE = 0;
static FILE** LOG_FDS = 0;
static ssize_t LOG_FDS_OPEN = 0;

#define facility_at(i) (LOG_FCL + ((i) << LOG_SRC_BITS))
#define facility_next(f) (f) += (1 << LOG_SRC_BITS)
#define facility_levels(f, i) *((f) + (i))

int log_setup(int logfiles)
{
	/* Check facilities count. */
	if (logfiles < 0) {
		return KNOTD_EINVAL;
	}

	/* Ensure minimum facilities count. */
	int facilities = LOGT_FILE + logfiles;

	/* Reserve space for facilities. */
	size_t new_size = facilities << LOG_SRC_BITS;
	LOG_FDS = 0;
	LOG_FDS_OPEN = 0;
	LOG_FCL = 0;
	LOG_FCL_SIZE = 0;
	LOG_FCL = malloc(new_size);
	if (!LOG_FCL) {
		return KNOTD_ENOMEM;
	}

	/* Reserve space for logfiles. */
	if (logfiles > 0) {
		LOG_FDS = malloc(sizeof(FILE*) * logfiles);
		if (!LOG_FDS) {
			free(LOG_FCL);
			LOG_FCL = 0;
			return KNOTD_ENOMEM;
		}
		memset(LOG_FDS, 0, sizeof(FILE*) * logfiles);
	}

	memset(LOG_FCL, 0, new_size);
	LOG_FCL_SIZE = new_size; // Assign only when all is set
	return KNOTD_EOK;
}



int log_init()
{
	/* Initialize globals. */
	LOG_FCL = 0;
	LOG_FCL_SIZE = 0;
	LOG_FDS = 0;
	LOG_FDS_OPEN = 0;

	/* Setup initial state. */
	int ret = KNOTD_EOK;
	int emask = LOG_MASK(LOG_WARNING)|LOG_MASK(LOG_ERR)|LOG_MASK(LOG_FATAL);
	int imask = LOG_MASK(LOG_INFO)|LOG_MASK(LOG_NOTICE);

	/* Add debug messages. */
	emask |= LOG_MASK(LOG_DEBUG);

	ret = log_setup(0);
	log_levels_set(LOGT_SYSLOG, LOG_ANY, emask);
	log_levels_set(LOGT_STDERR, LOG_ANY, emask);
	log_levels_set(LOGT_STDOUT, LOG_ANY, imask);

	/// \todo May change to LOG_DAEMON.
	setlogmask(LOG_UPTO(LOG_DEBUG));
	openlog(PACKAGE_NAME, LOG_PID, LOG_DAEMON);
	return ret;
}

void log_close()
{
	log_truncate();
	closelog();
}

void log_truncate()
{
	LOG_FCL_SIZE = 0;
	if (LOG_FCL) {
		free(LOG_FCL);
		LOG_FCL = 0;
	}
	if (LOG_FDS) {

		/* Close open logfiles. */
		for (int i = 0; i < LOG_FDS_OPEN; ++i) {
			fclose(LOG_FDS[i]);
		}

		free(LOG_FDS);
		LOG_FDS = 0;
		LOG_FDS_OPEN = 0;
	}
}

int log_isopen()
{
	return LOG_FCL_SIZE;
}

int log_open_file(const char* filename)
{
	// Check facility
	if (unlikely(!LOG_FCL_SIZE || LOGT_FILE + LOG_FDS_OPEN >= LOG_FCL_SIZE)) {
		return KNOTD_ERROR;
	}

	// Open file
	LOG_FDS[LOG_FDS_OPEN] = fopen(filename, "w");
	if (!LOG_FDS[LOG_FDS_OPEN]) {
		return KNOTD_EINVAL;
	}

	// Disable buffering
	setvbuf(LOG_FDS[LOG_FDS_OPEN], (char *)0, _IONBF, 0);

	return LOGT_FILE + LOG_FDS_OPEN++;
}

uint8_t log_levels(int facility, logsrc_t src)
{
	// Check facility
	if (unlikely(!LOG_FCL_SIZE || facility >= LOG_FCL_SIZE)) {
		return 0;
	}

	return *(LOG_FCL + (facility << LOG_SRC_BITS) + src);
}

int log_levels_set(int facility, logsrc_t src, uint8_t levels)
{
	// Check facility
	if (unlikely(!LOG_FCL_SIZE || facility >= LOG_FCL_SIZE)) {
		return KNOTD_EINVAL;
	}

	// Get facility pointer from offset
	uint8_t *lp = LOG_FCL + (facility << LOG_SRC_BITS);

	// Assign level if not multimask
	if (src != LOG_ANY) {
		*(lp + src) = levels;
	} else {
		// Any == set to all sources
		for (int i = 0; i <= LOG_ANY; ++i) {
			*(lp + i) = levels;
		}
	}

	return KNOTD_EOK;
}

int log_levels_add(int facility, logsrc_t src, uint8_t levels)
{
	uint8_t new_levels = log_levels(facility, src) | levels;
	return log_levels_set(facility, src, new_levels);
}

static int _log_msg(logsrc_t src, int level, const char *msg)
{
	if(!log_isopen()) {
		return KNOTD_ERROR;
	}

	int ret = 0;
	FILE *stream = stdout;
	uint8_t *f = facility_at(LOGT_SYSLOG);

	// Syslog
	if (facility_levels(f, src) & LOG_MASK(level)) {
		syslog(level, "%s", msg);
		ret = 1; // To prevent considering the message as ignored.
	}

	// Convert level to mask
	level = LOG_MASK(level);

	// Log streams
	for (int i = LOGT_STDERR; i < LOGT_FILE + LOG_FDS_OPEN; ++i) {

		// Check facility levels mask
		f = facility_at(i);
		if (facility_levels(f, src) & level) {

			// Select stream
			switch(i) {
			case LOGT_STDERR: stream = stderr; break;
			case LOGT_STDOUT: stream = stdout; break;
			default: stream = LOG_FDS[i - LOGT_FILE]; break;
			}

			// Print
			ret = fprintf(stream, "%s", msg);
			if (stream == stdout) {
				fflush(stream);
			}
		}
	}

	if (ret < 0) {
		return KNOTD_EINVAL;
	}

	return ret;
}

int log_msg(logsrc_t src, int level, const char *msg, ...)
{
	/* Buffer for log message. */
	char sbuf[4096];
	char *buf = sbuf;
	int buflen = sizeof(sbuf) - 1;

	/* Prefix error level. */
	const char *prefix = "";
	switch (level) {
	case LOG_DEBUG: break;
	case LOG_INFO:  break;
	case LOG_NOTICE:  prefix = "notice: "; break;
	case LOG_WARNING: prefix = "warning: "; break;
	case LOG_ERR:     prefix = "error: "; break;
	case LOG_FATAL:   prefix = "fatal: "; break;
	default: break;
	}

	/* Prepend prefix. */
	int plen = strlen(prefix);
	if (plen > 0) {
		strcpy(buf, prefix);
		buf += plen;
		buflen -= plen;
	}

	/* Compile log message. */
	int ret = 0;
	va_list ap;
	va_start(ap, msg);
	ret = vsnprintf(buf, buflen, msg, ap);
	va_end(ap);

	/* Send to logging facilities. */
	if (ret > 0) {
		ret = _log_msg(src, level, sbuf);
	}

	return ret;
}

int log_vmsg(logsrc_t src, int level, const char *msg, va_list ap)
{
	int ret = 0;
	char buf[2048];
	ret = vsnprintf(buf, sizeof(buf) - 1, msg, ap);

	if (ret > 0) {
		ret = _log_msg(src, level, buf);
	}

	return ret;
}

void hex_log(int source, const char *data, int length)
{
	int ptr = 0;
	for (; ptr < length; ptr++) {
		log_msg(source, LOG_DEBUG, "0x%02x ",
		        (unsigned char)*(data + ptr));
	}
	log_msg(source, LOG_DEBUG, "\n");
}
