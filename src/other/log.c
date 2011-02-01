#include <stdarg.h>
#include <stdio.h>

#include "log.h"
#include "common.h"

/// Global log-level.
static int _LOG_OPEN = 0;
static int _LOG_MASK = 0;

int log_open(int print_mask, int log_mask)
{
	setlogmask(log_mask);

	/// \todo May change to LOG_DAEMON.
	openlog(PROJECT_NAME, LOG_CONS | LOG_PID, LOG_LOCAL1);
	_LOG_MASK = print_mask;
	_LOG_OPEN = 1;
	return 0;
}

int log_close()
{
	_LOG_OPEN = 0;
	_LOG_MASK = 0;
	closelog();
	return 0;
}

int log_isopen()
{
	return _LOG_OPEN;
}

int print_msg(int level, const char *msg, ...)
{
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
}
