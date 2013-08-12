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
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <limits.h>

#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "common.h"
#include "common/evqueue.h"
#include "knot/knot.h"
#include "knot/server/server.h"
#include "knot/ctl/process.h"
#include "knot/ctl/remote.h"
#include "knot/conf/conf.h"
#include "knot/conf/logconf.h"
#include "knot/server/zones.h"
#include "knot/server/tcp-handler.h"

/*----------------------------------------------------------------------------*/

/* Signal flags. */
static volatile short sig_req_stop = 0;
static volatile short sig_req_reload = 0;
static volatile short sig_stopping = 0;

#ifdef INTEGRITY_CHECK
static volatile short sig_integrity_check = 0;
int check_iteration = 0;
char *zone = NULL;
#endif /* INTEGRITY_CHECK */

// Cleanup handler
static int do_cleanup(server_t *server, char *configf, char *pidf);

// SIGINT signal handler
void interrupt_handle(int s)
{
	// Reload configuration
	if (s == SIGHUP) {
		sig_req_reload = 1;
		return;
	}

	// Stop server
	if (s == SIGINT || s == SIGTERM) {
		if (sig_stopping == 0) {
			sig_req_stop = 1;
			sig_stopping = 1;
		} else {
			exit(1);
		}
	}

#ifdef INTEGRITY_CHECK
	// Start zone integrity check
	if (s == SIGUSR1) {
		sig_integrity_check = 1;
		return;
	}
#endif /* INTEGRITY_CHECK */
}

void help(void)
{
	printf("Usage: %sd [parameters]\n",
	       PACKAGE_NAME);
	printf("\nParameters:\n"
	       " -c, --config [file] Select configuration file.\n"
#ifdef INTEGRITY_CHECK
	       " -z, --zone [zone]   Set zone to check. Send SIGUSR1 to trigger\n"
	       "                     integrity check.\n"
#endif /* INTEGRITY_CHECK */
	       " -d, --daemonize     Run server as a daemon.\n"
	       " -v, --verbose       Verbose mode - additional runtime information.\n"
	       " -V, --version       Print version of the server.\n"
	       " -h, --help          Print help and usage.\n");
}

int main(int argc, char **argv)
{
	// Parse command line arguments
	int c = 0, li = 0;
	int verbose = 0;
	int daemonize = 0;
	char* config_fn = NULL;

	/* Long options. */
	struct option opts[] = {
		{"config",    required_argument, 0, 'c'},
#ifdef INTEGRITY_CHECK
		{"zone",      required_argument, 0, 'z'},
#endif /* INTEGRITY_CHECK */
		{"daemonize", no_argument,       0, 'd'},
		{"verbose",   no_argument,       0, 'v'},
		{"version",   no_argument,       0, 'V'},
		{"help",      no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

#ifndef INTEGRITY_CHECK
	while ((c = getopt_long(argc, argv, "c:dvVh", opts, &li)) != -1) {
#else
	while ((c = getopt_long(argc, argv, "c:z:dvVh", opts, &li)) != -1) {
#endif /* INTEGRITY_CHECK */
		switch (c)
		{
		case 'c':
			config_fn = strdup(optarg);
			break;
#ifdef INTEGRITY_CHECK
		case 'z':
			if (optarg[strlen(optarg) - 1] != '.') {
				zone = strcdup(optarg, ".");
			} else {
				zone = strdup(optarg);
			}
			break;
#endif /* INTEGRITY_CHECK */
		case 'd':
			daemonize = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'V':
			printf("%s, version %s\n", "Knot DNS", PACKAGE_VERSION);
			return 0;
		case 'h':
		case '?':
			free(config_fn);
			help();
			return 0;
		default:
			free(config_fn);
			help();
			return 1;
		}
	}

	// Now check if we want to daemonize
	if (daemonize) {
		if (daemon(1, 0) != 0) {
			free(config_fn);
			fprintf(stderr, "Daemonization failed, "
					"shutting down...\n");
			return 1;
		}
	}

	// Register service and signal handler
	struct sigaction emptyset;
	memset(&emptyset, 0, sizeof(struct sigaction));
	emptyset.sa_handler = interrupt_handle;
	sigemptyset(&emptyset.sa_mask);
	emptyset.sa_flags = 0;
	sigaction(SIGALRM, &emptyset, NULL); // Interrupt
	sigaction(SIGPIPE, &emptyset, NULL); // Mask
	rcu_register_thread();

	// Initialize log
	log_init();

	// Verbose mode
	if (verbose) {
		int mask = LOG_MASK(LOG_INFO)|LOG_MASK(LOG_DEBUG);
		log_levels_add(LOGT_STDOUT, LOG_ANY, mask);
	}

	// Initialize pseudorandom number generator
	srand(time(0));

	// Find implicit configuration file
	if (!config_fn) {
		config_fn = conf_find_default();
	}

	// Find absolute path for config file
	if (config_fn[0] != '/')
	{
		// Get absolute path to cwd
		char *rpath = realpath(config_fn, NULL);
		if (rpath == NULL) {
			log_server_error("Couldn't get absolute path for configuration file '%s' - "
			                 "%s.\n", config_fn, strerror(errno));
			free(config_fn);
			return 1;
		} else {
			free(config_fn);
			config_fn = rpath;
		}
	}

	// Create server
	server_t *server = server_create();

	// Initialize configuration
	rcu_read_lock();
	conf_add_hook(conf(), CONF_LOG, log_conf_hook, 0);
	conf_add_hook(conf(), CONF_ALL, server_conf_hook, server);
	rcu_read_unlock();

	/* POSIX 1003.1e capabilities. */
#ifdef HAVE_CAP_NG_H

	/* Drop all capabilities. */
	if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
		capng_clear(CAPNG_SELECT_BOTH);


		/* Retain ability to set capabilities and FS access. */
		capng_type_t tp = CAPNG_EFFECTIVE|CAPNG_PERMITTED;
		capng_update(CAPNG_ADD, tp, CAP_SETPCAP);
		capng_update(CAPNG_ADD, tp, CAP_DAC_OVERRIDE);
		capng_update(CAPNG_ADD, tp, CAP_CHOWN); /* Storage ownership. */

		/* Allow binding to privileged ports.
		 * (Not inheritable)
		 */
		capng_update(CAPNG_ADD, tp, CAP_NET_BIND_SERVICE);

		/* Allow setuid/setgid. */
		capng_update(CAPNG_ADD, tp, CAP_SETUID);
		capng_update(CAPNG_ADD, tp, CAP_SETGID);

		/* Allow priorities changing. */
		capng_update(CAPNG_ADD, tp, CAP_SYS_NICE);

		/* Apply */
		if (capng_apply(CAPNG_SELECT_BOTH) < 0) {
			log_server_error("Couldn't set process capabilities - "
			                 "%s.\n", strerror(errno));
		}
	} else {
		log_server_info("User uid=%d is not allowed to set "
		                "capabilities, skipping.\n", getuid());
	}
#endif /* HAVE_CAP_NG_H */

	// Open configuration
	log_server_info("Reading configuration '%s' ...\n", config_fn);
	int conf_ret = conf_open(config_fn);
	if (conf_ret != KNOT_EOK) {
		if (conf_ret == KNOT_ENOENT) {
			log_server_error("Couldn't open configuration file "
			                 "'%s'.\n", config_fn);
		} else {
			log_server_error("Failed to load configuration '%s'.\n",
			                 config_fn);
		}
		return do_cleanup(server, config_fn, NULL);
	} else {
		log_server_info("Configured %d interfaces and %d zones.\n",
				conf()->ifaces_count, conf()->zones_count);
	}

	/* Alter privileges. */
	log_update_privileges(conf()->uid, conf()->gid);
	if (proc_update_privileges(conf()->uid, conf()->gid) != KNOT_EOK)
		return do_cleanup(server, config_fn, NULL);

	/* Check and create PID file. */
	long pid = (long)getpid();
	char *pidf = NULL;
	char *cwd = NULL;
	if (daemonize) {
		if ((pidf = pid_check_and_create()) == NULL)
			return do_cleanup(server, config_fn, pidf);
		log_server_info("Server started as a daemon, PID = %ld\n", pid);
		log_server_info("PID stored in '%s'\n", pidf);
		if ((cwd = malloc(PATH_MAX)) != NULL)
			cwd = getcwd(cwd, PATH_MAX);
		if (chdir("/") != 0)
			log_server_warning("Server can't change working directory.\n");
	} else {
		log_server_info("Server started in foreground, PID = %ld\n", pid);
		log_server_info("Server running without PID file.\n");
	}

	/* Load zones and add hook. */
	zones_ns_conf_hook(conf(), server->nameserver);
	conf_add_hook(conf(), CONF_ALL, zones_ns_conf_hook, server->nameserver);

	// Run server
	int res = 0;
	log_server_info("Starting server...\n");
	if ((server_start(server)) == KNOT_EOK) {
		size_t zcount = server->nameserver->zone_db->zone_count;
		if (!zcount) {
			log_server_warning("Server started, but no zones served.\n");
		}

		// Setup signal handler
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = interrupt_handle;
		sigemptyset(&sa.sa_mask);
		sigaction(SIGINT,  &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
		sigaction(SIGHUP,  &sa, NULL);
		sigaction(SIGPIPE, &sa, NULL);
#ifdef INTEGRITY_CHECK
		sigaction(SIGUSR1, &sa, NULL);
#endif /* INTEGRITY_CHECK */
		sa.sa_flags = 0;
		pthread_sigmask(SIG_BLOCK, &sa.sa_mask, NULL);

		/* Bind to control interface. */
		uint8_t buf[SOCKET_MTU_SZ];
		size_t buflen = sizeof(buf);
		int remote = -1;
		if (conf()->ctl.iface != NULL) {
			conf_iface_t *ctl_if = conf()->ctl.iface;
			memset(buf, 0, buflen);
			if (ctl_if->port)
				snprintf((char*)buf, buflen, "@%d", ctl_if->port);
			/* Log control interface description. */
			log_server_info("Binding remote control interface "
					"to %s%s\n",
					ctl_if->address, (char*)buf);
			remote = remote_bind(ctl_if);
		}

		/* Run event loop. */
		for(;;) {
			pthread_sigmask(SIG_UNBLOCK, &sa.sa_mask, NULL);
			int ret = remote_poll(remote);
			pthread_sigmask(SIG_BLOCK, &sa.sa_mask, NULL);

			/* Events. */
			if (ret > 0) {
				ret = remote_process(server, conf()->ctl.iface,
				                     remote, buf, buflen);
				switch(ret) {
				case KNOT_CTL_STOP:
					sig_req_stop = 1;
					break;
				default:
					break;
				}
			}

			/* Interrupts. */
			if (sig_req_stop) {
				sig_req_stop = 0;
				server_stop(server);
				break;
			}
			if (sig_req_reload) {
				sig_req_reload = 0;
				server_reload(server, config_fn);
			}
#ifdef INTEGRITY_CHECK
			if (zone == NULL)
				sig_integrity_check = 0;
			if (sig_integrity_check) {
				log_server_info("Starting integrity check of "
				                "zone: %s\n", zone);
				knot_dname_t *zdn =
					knot_dname_new_from_str(zone,
					                        strlen(zone),
					                        NULL);
				knot_zone_t *z =
					knot_zonedb_find_zone(server->nameserver->zone_db,
					                      zdn);
				int ic_ret =
					knot_zone_contents_integrity_check(z->contents);
				log_server_info("Integrity check: %d errors "
				                "discovered.\n", ic_ret);
				knot_dname_free(&zdn);
				log_server_info("Integrity check %d finished.\n",
				                check_iteration);
				++check_iteration;
			}
#endif /* INTEGRITY_CHECK */
		}
		pthread_sigmask(SIG_UNBLOCK, &sa.sa_mask, NULL);

		/* Close remote control interface */
		if (remote > -1) {
			close(remote);

			/* Remove control socket.  */
			conf_iface_t *ctl_if = conf()->ctl.iface;
			if (ctl_if && ctl_if->family == AF_UNIX)
				unlink(conf()->ctl.iface->address);
		}

		if ((server_wait(server)) != KNOT_EOK) {
			log_server_error("An error occured while "
					 "waiting for server to finish.\n");
			res = 1;
		} else {
			log_server_info("Server finished.\n");
		}

	} else {
		log_server_fatal("An error occured while "
				 "starting the server.\n");
		res = 1;
	}

	log_server_info("Shut down.\n");
	log_close();

	/* Cleanup. */
	if (pidf && pid_remove(pidf) < 0)
		log_server_warning("Failed to remove PID file.\n");
	do_cleanup(server, config_fn, pidf);

#ifdef INTEGRITY_CHECK
	free(zone);
#endif /* INTEGRITY_CHECK */

	if (!daemonize) {
		fflush(stdout);
		fflush(stderr);
	}

	/* Return to original working directory. */
	if (cwd) {
		if (chdir(cwd) != 0)
			log_server_warning("Server can't change working directory.\n");
		free(cwd);
	}

	return res;
}

static int do_cleanup(server_t *server, char *configf, char *pidf)
{
	/* Free alloc'd variables. */
	if (server) {
		server_wait(server);
		server_destroy(&server);
	}
	free(configf);
	free(pidf);

	/* Unhook from RCU */
	rcu_unregister_thread();

	return 1;
}
