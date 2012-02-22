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
	if (conf() && conf()->pidfile != NULL) {
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
			return KNOTD_ENOENT;
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
			return KNOTD_ENOENT;
		}

		// Convert pid
		char* ep = 0;
		unsigned long pid = strtoul(buf, &ep, 10);
		if ((errno == ERANGE) || (*ep && !isspace(*ep))) {
			return KNOTD_ERANGE;
		}

		return (pid_t)pid;
	}

	return KNOTD_EINVAL;
}

int pid_write(const char* fn)
{
	if (!fn) {
		return KNOTD_EINVAL;
	}

	// Convert
	char buf[64];
	int wbytes = 0;
	wbytes = snprintf(buf, sizeof(buf), "%lu", (unsigned long) getpid());
	if (wbytes < 0) {
		return KNOTD_EINVAL;
	}

	// Write
	FILE *fp = fopen(fn, "w");
	if (fp) {
		int rc = fwrite(buf, wbytes, 1, fp);
		fclose(fp);
		if (rc < 0) {
			return KNOTD_ERROR;
		}

		return 0;
	}

	return KNOTD_ENOENT;
}

int pid_remove(const char* fn)
{
	if (unlink(fn) < 0) {
		return KNOTD_EINVAL;
	}

	return KNOTD_EOK;
}

int pid_running(pid_t pid)
{
	return kill(pid, 0) == 0;
}

