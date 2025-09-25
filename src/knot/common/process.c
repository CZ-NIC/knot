/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "knot/common/log.h"
#include "knot/common/process.h"
#include "knot/conf/conf.h"
#include "libknot/errcode.h"

static char* pid_filename(void)
{
	conf_val_t val = conf_get(conf(), C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&val, NULL);
	val = conf_get(conf(), C_SRV, C_PIDFILE);
	char *pidfile = conf_abs_path(&val, rundir);
	free(rundir);

	return pidfile;
}

static pid_t pid_read(const char *filename)
{
	if (filename == NULL) {
		return 0;
	}

	size_t len = 0;
	char buf[64] = { 0 };

	FILE *fp = fopen(filename, "r");
	if (fp == NULL) {
		return 0;
	}

	/* Read the content of the file. */
	len = fread(buf, 1, sizeof(buf) - 1, fp);
	(void)fclose(fp);
	if (len < 1) {
		return 0;
	}

	/* Convert pid. */
	errno = 0;
	char *end = 0;
	unsigned long pid = strtoul(buf, &end, 10);
	if (end == buf || *end != '\0'|| errno != 0) {
		return 0;
	}

	return (pid_t)pid;
}

static int pid_write(const char *filename, pid_t pid)
{
	if (filename == NULL) {
		return KNOT_EINVAL;
	}

	/* Convert. */
	char buf[64];
	int len = 0;
	len = snprintf(buf, sizeof(buf), "%lu", (unsigned long)pid);
	if (len < 0 || len >= sizeof(buf)) {
		return KNOT_ENOMEM;
	}

	/* Create file. */
	int ret = KNOT_EOK;
	int fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
	if (fd >= 0) {
		if (write(fd, buf, len) != len) {
			ret = knot_map_errno();
		}
		if (close(fd) == -1 && ret == KNOT_EOK) {
			ret = knot_map_errno();
		}
	} else {
		ret = knot_map_errno();
	}

	return ret;
}

unsigned long pid_check_and_create(void)
{
	struct stat st;
	char *pidfile = pid_filename();
	pid_t pid = pid_read(pidfile);

	/* Check PID for existence and liveness. */
	if (pid > 0 && pid_running(pid)) {
		log_fatal("server PID found, already running");
		free(pidfile);
		return 0;
	} else if (stat(pidfile, &st) == 0) {
		assert(pidfile);
		log_warning("removing stale PID file '%s'", pidfile);
		pid_cleanup();
	}

	/* Get current PID. */
	pid = getpid();

	/* Create a PID file. */
	int ret = pid_write(pidfile, pid);
	if (ret != KNOT_EOK) {
		log_fatal("failed to create a PID file '%s' (%s)", pidfile,
		          knot_strerror(ret));
		free(pidfile);
		return 0;
	}
	free(pidfile);

	return (unsigned long)pid;
}

void pid_cleanup(void)
{
	char *pidfile = pid_filename();
	if (pidfile != NULL) {
		(void)unlink(pidfile);
		free(pidfile);
	}
}

bool pid_running(pid_t pid)
{
	return kill(pid, 0) == 0;
}

int proc_update_privileges(int uid, int gid)
{
#ifdef HAVE_SETGROUPS
	/* Drop supplementary groups. */
	if ((uid_t)uid != getuid() || (gid_t)gid != getgid()) {
		if (setgroups(0, NULL) < 0) {
			log_warning("failed to drop supplementary groups for "
				    "UID %d (%s)", getuid(), strerror(errno));
		}
# ifdef HAVE_INITGROUPS
		struct passwd *pw;
		if ((pw = getpwuid(uid)) == NULL) {
			log_warning("failed to get passwd entry for UID %d (%s)",
			            uid, strerror(errno));
		} else {
			if (initgroups(pw->pw_name, gid) < 0) {
				log_warning("failed to set supplementary groups "
					    "for UID %d (%s)", uid, strerror(errno));
			}
		}
# endif /* HAVE_INITGROUPS */
	}
#endif /* HAVE_SETGROUPS */

	/* Watch uid/gid. */
	if ((gid_t)gid != getgid()) {
		log_info("changing GID to %d", gid);
		if (setregid(gid, gid) < 0) {
			log_error("failed to change GID to %d", gid);
			return KNOT_ERROR;
		}
	}
	if ((uid_t)uid != getuid()) {
		log_info("changing UID to %d", uid);
		if (setreuid(uid, uid) < 0) {
			log_error("failed to change UID to %d", uid);
			return KNOT_ERROR;
		}
	}

	return KNOT_EOK;
}
