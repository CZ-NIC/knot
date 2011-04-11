#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include "knot/common.h"
#include "knot/ctl/process.h"
#include "knot/conf/conf.h"
#include "knot/other/error.h"

char* pid_filename()
{
	conf_read_lock();

	/* Read configuration. */
	char* ret = 0;
	if (conf()) {
		ret = strdup(conf()->pidfile);
	}

	conf_read_unlock();

	return ret;
}

pid_t pid_read(const char* fn)
{
	char buf[64];

	if (fn) {
		FILE *fp = fopen(fn, "r");
		if (!fp) {
			return KNOT_ENOENT;
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
			return KNOT_ENOENT;
		}

		// Convert pid
		char* ep = 0;
		unsigned long pid = strtoul(buf, &ep, 10);
		if ((errno == ERANGE) || (*ep && !isspace(*ep))) {
			return KNOT_ERANGE;
		}

		return (pid_t)pid;
	}

	return KNOT_EINVAL;
}

int pid_write(const char* fn)
{
	if (!fn) {
		return KNOT_EINVAL;
	}

	// Convert
	char buf[64];
	int wbytes = 0;
	wbytes = snprintf(buf, sizeof(buf), "%lu", (unsigned long) getpid());
	if (wbytes < 0) {
		return KNOT_EINVAL;
	}

	// Write
	FILE *fp = fopen(fn, "w");
	if (fp) {
		int rc = fwrite(buf, wbytes, 1, fp);
		fclose(fp);
		if (rc < 0) {
			return KNOT_ERROR;
		}

		return 0;
	}

	return KNOT_ENOENT;
}

int pid_remove(const char* fn)
{
	if (unlink(fn) < 0) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int pid_running(pid_t pid)
{
	return kill(pid, 0) == 0;
}

