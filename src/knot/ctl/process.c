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
#include <grp.h>
#include <unistd.h>
#include <assert.h>
#include <sys/wait.h>

#include "knot/common.h"
#include "knot/ctl/process.h"
#include "knot/conf/conf.h"

char* pid_filename()
{
	rcu_read_lock();

	/* Read configuration. */
	char* ret = 0;
	if (conf() && conf()->pidfile != NULL) {
		ret = strdup(conf()->pidfile);
	}

	rcu_read_unlock();

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
		perror("unlink");
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int pid_running(pid_t pid)
{
	return kill(pid, 0) == 0;
}

void proc_update_privileges(int uid, int gid)
{
#ifdef HAVE_SETGROUPS
	/* Drop supplementary groups. */
	if (uid != getuid() || gid != getgid()) {
		if (setgroups(0, NULL) < 0) {
			log_server_warning("Failed to drop supplementary groups"
			                   " for uid '%d' (%s).\n",
			                   getuid(), strerror(errno));
		}
	}
#endif
	
	/* Watch uid/gid. */
	if (gid != getgid()) {
		log_server_info("Changing group id to '%d'.\n", gid);
		if (setregid(gid, gid) < 0) {
			log_server_error("Failed to change gid to '%d'.\n",
			                 gid);
		}
	}
	if (uid != getuid()) {
		log_server_info("Changing user id to '%d'.\n", uid);
		if (setreuid(uid, uid) < 0) {
			log_server_error("Failed to change uid to '%d'.\n",
			                 uid);
		}
	}
	
	/* Check storage writeability. */
	char *lfile = strcdup(conf()->storage, "/knot.lock");
	assert(lfile != NULL);
	FILE* fp = fopen(lfile, "w");
	if (fp == NULL) {
		log_server_warning("Storage directory '%s' is not writeable.\n",
		                   conf()->storage);
	} else {
		fclose(fp);
		unlink(lfile);
	}
	free(lfile);
}

pid_t pid_wait(pid_t proc, int *rc)
{
	/* Wait for finish. */
	sigset_t newset;
	sigfillset(&newset);
	sigprocmask(SIG_BLOCK, &newset, 0);
	proc = waitpid(proc, rc, 0);
	sigprocmask(SIG_UNBLOCK, &newset, 0);
	return proc;
}


pid_t pid_start(const char *argv[], int argc, int drop_privs)
{
	pid_t chproc = fork();
	if (chproc == 0) {
	
		/* Alter privileges. */
		if (drop_privs) {
			proc_update_privileges(conf()->uid, conf()->gid);
		}

		/* Duplicate, it doesn't run from stack address anyway. */
		char **args = malloc((argc + 1) * sizeof(char*));
		memset(args, 0, (argc + 1) * sizeof(char*));
		int ci = 0;
		for (int i = 0; i < argc; ++i) {
			if (strlen(argv[i]) > 0) {
				args[ci++] = strdup(argv[i]);
			}
		}
		args[ci] = 0;

		/* Execute command. */
		fflush(stdout);
		fflush(stderr);
		execvp(args[0], args);

		/* Execute failed. */
		log_server_error("Failed to run executable '%s'\n", args[0]);
		for (int i = 0; i < argc; ++i) {
			free(args[i]);
		}
		free(args);

		exit(1);
		return -1;
	}
	
	return chproc;
}

int cmd_exec(const char *argv[], int argc)
{
	int ret = 0;
	pid_t proc = pid_start(argv, argc, 0);
	pid_wait(proc, &ret);
	return ret;
}
