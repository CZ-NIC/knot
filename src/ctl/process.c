#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "process.h"
#include "log.h"

/*! \todo REMOVE this when configuration allows
 *        specification of an explicit PID file path.
 */
static char *get_temporary_fn(const char* fn)
{
	char* home = getenv("HOME");
	int len = strlen(home) + strlen(fn) + 1;
	char* ret = malloc(len);
	memset(ret, 0, len);
	strcpy(ret, home);
	strcat(ret, fn);
	return ret;
}

pid_t pid_read(const char* fn)
{
	char buf[64];

	if (fn) {
		char* tmp = get_temporary_fn(fn);
		FILE *fp = fopen(tmp, "r");
		free(tmp);

		if (!fp) {
			return PID_NOFILE;
		}

		int rc = fread(buf, sizeof(buf), 1, fp);
		fclose(fp);

		// Check read result
		if (rc < 1) {
			return PID_EMPTY;
		}

		// Convert pid
		char* ep = 0;
		unsigned long pid = strtoul(buf, &ep, 10);
		if ((errno == ERANGE) || (*ep && !isspace(*ep))) {
			return PID_INVAL;
		}

		return (pid_t)pid;
	}

	return PID_NOFILE;
}

int pid_write(const char* fn)
{
	if (!fn) {
		return PID_NOFILE;
	}

	// Convert
	char buf[64];
	int wbytes = 0;
	wbytes = snprintf(buf, sizeof(buf), "%lu", (unsigned long) getpid());
	if (wbytes < 0) {
		return PID_INVAL;
	}

	// Write
	char* tmp = get_temporary_fn(fn);
	FILE *fp = fopen(tmp, "w");
	free(tmp);

	if (fp) {
		int rc = fwrite(buf, wbytes, 1, fp);
		fclose(fp);
		if (rc < 0) {
			return PID_NOFILE;
		}

		return 0;
	}

	return PID_NOFILE;
}

int pid_remove(const char* fn)
{
	char* tmp = get_temporary_fn(fn);
	int rc = unlink(tmp);
	free(tmp);
	return rc;
}

