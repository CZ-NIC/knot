#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "process.h"
#include "log.h"

char* pid_filename()
{
	// Construct filename
	const char* fn = "/cutedns.pid";
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
		FILE *fp = fopen(fn, "r");
		if (!fp) {
			return PID_NOFILE;
		}

		int readb = 0;
		int rc = fread(buf, 1, 1, fp);
		while (rc > 0) {
			if (++readb == sizeof(buf) - 1) {
				break;
			}
			rc = fread(buf + readb, 1, 1, fp);
		}
		buf[readb] = '\0';
		fclose(fp);

		// Check read result
		if (readb < 1) {
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
	FILE *fp = fopen(fn, "w");

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
	return unlink(fn);
}

