#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "lists.h"
#include "common.h"
#include "conf.h"

/*! Log source table. */
static uint8_t *LOG_FCL = 0;
static volatile size_t LOG_FCL_SIZE = 0;
static FILE** LOG_FDS = 0;
static size_t LOG_FDS_OPEN = 0;

int log_setup(int facilities)
{
	/* Check facilities count. */
	if (facilities <= 0) {
		return -1;
	}

	/* Reserve space for facilities. */
	LOG_FDS = 0;
	LOG_FDS_OPEN = 0;
	LOG_FCL_SIZE = facilities << LOG_SRC_BITS;
	LOG_FCL = malloc(LOG_FCL_SIZE);
	if (!LOG_FCL) {
		LOG_FCL_SIZE = 0;
		return -1;
	}

	/* Reserve space for logfiles. */
	int files = (facilities - LOGT_FILE);
	if (files > 0) {
		LOG_FDS = malloc(sizeof(FILE*) * files);
		if (!LOG_FDS) {
			LOG_FCL_SIZE = 0;
			free(LOG_FCL);
			LOG_FCL = 0;
			return -1;
		}
	}

	memset(LOG_FDS, 0, sizeof(FILE*) * files);
	memset(LOG_FCL, 0, LOG_FCL_SIZE);
	return 0;
}



int log_init()
{
	/* Initialize globals. */
	LOG_FCL = 0;
	LOG_FCL_SIZE = 0;
	LOG_FDS = 0;
	LOG_FDS_OPEN = 0;

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
	if (unlikely(!LOG_FCL || LOGT_FILE + LOG_FDS_OPEN >= LOG_FCL_SIZE)) {
		return -1;
	}

	// Open file
	LOG_FDS[LOG_FDS_OPEN] = fopen(filename, "w");
	if (!LOG_FDS[LOG_FDS_OPEN]) {
		return -1;
	}

	return LOGT_FILE + LOG_FDS_OPEN++;
}

uint8_t log_levels(int facility, logsrc_t src)
{
	// Check facility
	if (unlikely(!LOG_FCL || facility >= LOG_FCL_SIZE)) {
		return 0;
	}

	return *(LOG_FCL + (facility << LOG_SRC_BITS) + src);
}

int log_levels_set(int facility, logsrc_t src, uint8_t levels)
{
	// Check facility
	if (unlikely(!LOG_FCL || facility >= LOG_FCL_SIZE)) {
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

int print_msg(int level, const char *msg, ...)
{
	//! \todo FIXME
/*
	// Get output stream
	va_list ap;
	FILE *stream = stdout;
	if (level & (LOG_ERR | LOG_WARNING | LOG_CRIT | LOG_ALERT)) {
		stream = stderr;
	}

	// Check mask
	int ret = 0;
	if (LOG_MASK(level) & _LOG_MASK || level == LOG_DEBUG) {
		va_start(ap, msg);
		ret = vfprintf(stream, msg, ap);
		va_end(ap);
	}

	return ret;
*/

	return 0;
}
