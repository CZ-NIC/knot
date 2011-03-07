#include <config.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "other/log.h"
#include "lib/lists.h"
#include "conf/conf.h"

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
		return -1;
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
		return -1;
	}

	/* Reserve space for logfiles. */
	if (logfiles > 0) {
		LOG_FDS = malloc(sizeof(FILE*) * logfiles);
		if (!LOG_FDS) {
			free(LOG_FCL);
			LOG_FCL = 0;
			return -1;
		}
		memset(LOG_FDS, 0, sizeof(FILE*) * logfiles);
	}

	memset(LOG_FCL, 0, new_size);
	LOG_FCL_SIZE = new_size; // Assign only when all is set
	return 0;
}



int log_init()
{
	/* Initialize globals. */
	LOG_FCL = 0;
	LOG_FCL_SIZE = 0;
	LOG_FDS = 0;
	LOG_FDS_OPEN = 0;

	/* Setup initial state. */
	int bmask = LOG_MASK(LOG_ERR)|LOG_MASK(LOG_FATAL);
	log_setup(0);
	log_levels_set(LOGT_SYSLOG, LOG_ANY, bmask);
	log_levels_set(LOGT_STDERR, LOG_ANY, bmask);

	/// \todo May change to LOG_DAEMON.
	setlogmask(LOG_UPTO(LOG_DEBUG));
	openlog(PROJECT_NAME, LOG_CONS | LOG_PID, LOG_LOCAL1);
	return 0;
}

int log_close()
{
	log_truncate();
	closelog();
	return 0;
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
		return -1;
	}

	// Open file
	LOG_FDS[LOG_FDS_OPEN] = fopen(filename, "w");
	if (!LOG_FDS[LOG_FDS_OPEN]) {
		return -1;
	}

	// Disable buffering
	setvbuf(LOG_FDS[LOG_FDS_OPEN], (char *)NULL, _IONBF, 0);

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
		return -1;
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

	return 0;
}

int log_levels_add(int facility, logsrc_t src, uint8_t levels)
{
	uint8_t new_levels = log_levels(facility, src) | levels;
	return log_levels_set(facility, src, new_levels);
}

static int _log_msg(logsrc_t src, int level, const char *msg)
{
	if(!log_isopen()) {
		return -1;
	}

	int ret = 0;
	FILE *stream = stdout;
	uint8_t *f = facility_at(LOGT_SYSLOG);

	// Convert level to mask
	level = LOG_MASK(level);

	// Syslog
	if (facility_levels(f, src) & level) {
		syslog(level, msg, "");
		ret = 1; // To prevent considering the message as ignored.
	}

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
			ret = fprintf(stream, msg, "");
		}
	}

	return ret;
}

int log_msg(logsrc_t src, int level, const char *msg, ...)
{
	int ret = 0;
	char buf[2048];
	va_list ap;
	va_start(ap, msg);
	ret = vsnprintf(buf, sizeof(buf) - 1, msg, ap);
	va_end(ap);

	if (ret > 0) {
		ret = _log_msg(src, level, buf);
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
