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
#include "common.h"

#include "knot/common.h"
#include "knot/other/error.h"
#include "knot/server/server.h"
#include "zcompile/zcompile.h"
#include "knot/ctl/process.h"
#include "knot/conf/conf.h"
#include "knot/conf/logconf.h"
#include "common/evqueue.h"
#include "knot/server/zones.h"

/*----------------------------------------------------------------------------*/

/* Signal flags. */
static volatile short sig_req_stop = 0;
static volatile short sig_req_reload = 0;
static volatile short sig_stopping = 0;

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
			log_server_notice("OK! Exiting immediately.\n");
			exit(1);
		}
	}
}

void help(int argc, char **argv)
{
	printf("Usage: %sd [parameters]\n",
	       PACKAGE_NAME);
	printf("Parameters:\n"
	       " -c, --config [file] Select configuration file.\n"
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
	char* config_fn = 0;
	
	/* Long options. */
	struct option opts[] = {
		{"config",    required_argument, 0, 'c'},
		{"daemonize", no_argument,       0, 'd'},
		{"verbose",   no_argument,       0, 'v'},
		{"version",   no_argument,       0, 'V'},
		{"help",      no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};
	
	while ((c = getopt_long(argc, argv, "c:dvVh", opts, &li)) != -1) {
		switch (c)
		{
		case 'c':
			config_fn = strdup(optarg);
			break;
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
		default:
			help(argc, argv);
			return 1;
		}
	}

	// Now check if we want to daemonize
	if (daemonize) {
		if (daemon(1, 0) != 0) {
			fprintf(stderr, "Daemonization failed, "
					"shutting down...\n");
			return 1;
		}
	}

	// Register service and signal handler
	struct sigaction emptyset;
	emptyset.sa_handler = interrupt_handle;
	sigemptyset(&emptyset.sa_mask);
	emptyset.sa_flags = 0;
	sigaction(SIGALRM, &emptyset, NULL); // Interrupt

	// Setup event queue
	evqueue_set(evqueue_new());

	// Initialize log
	log_init();

	// Verbose mode
	if (verbose) {
		int mask = LOG_MASK(LOG_INFO)|LOG_MASK(LOG_DEBUG);
		log_levels_add(LOGT_STDOUT, LOG_ANY, mask);
	}

	// Initialize pseudorandom number generator
	srand(time(0));

	// Create server
	server_t *server = server_create();

	// Initialize configuration
	conf_read_lock();
	conf_add_hook(conf(), CONF_LOG, log_conf_hook, 0);
	conf_add_hook(conf(), CONF_LOG, zones_ns_conf_hook, server->nameserver);
	conf_add_hook(conf(), CONF_LOG, server_conf_hook, server);
	conf_read_unlock();

	// Find implicit configuration file
	if (!config_fn) {
		config_fn = conf_find_default();
	}

	// Find absolute path for config file
	if (config_fn[0] != '/')
	{
		// Get absolute path to cwd
		size_t cwbuflen = 64;
		char *cwbuf = malloc((cwbuflen + 2) * sizeof(char));
		while (getcwd(cwbuf, cwbuflen) == 0) {
			cwbuflen *= 2;
			cwbuf = realloc(cwbuf, (cwbuflen + 2) * sizeof(char));
		}
		cwbuflen = strlen(cwbuf);

		// Append ending slash
		if (cwbuf[cwbuflen - 1] != '/') {
			cwbuf = strcat(cwbuf, "/");
		}

		// Assemble path to config file
		char *abs_cfg = strcdup(cwbuf, config_fn);
		free(config_fn);
		free(cwbuf);
		config_fn = abs_cfg;
	}

	// Open configuration
	log_server_info("Parsing configuration '%s' ...\n", config_fn);
	if (conf_open(config_fn) != KNOTD_EOK) {

		log_server_error("Failed to parse configuration file '%s'.\n",
				 config_fn);
		server_destroy(&server);
		free(config_fn);
		return 1;
	} else {
		log_server_info("Configured %d interfaces and %d zones.\n",
				conf()->ifaces_count, conf()->zones_count);
	}
	log_server_info("\n");

	// Create server instance
	char* pidfile = pid_filename();

	// Run server
	int res = 0;
	log_server_info("Starting server...\n");
	if ((res = server_start(server)) == KNOTD_EOK) {

		// Save PID
		int has_pid = 1;
		int rc = pid_write(pidfile);
		if (rc < 0) {
			has_pid = 0;
			log_server_warning("Failed to create "
					   "PID file '%s'.\n", pidfile);
		}

		// Change directory if daemonized
		if (daemonize) {
			log_server_info("Server started as a daemon, "
					"PID = %ld\n", (long)getpid());
			res = chdir("/");
		} else {
			log_server_info("Server started in foreground, "
					"PID = %ld\n", (long)getpid());
		}
		if (has_pid) {
			log_server_info("PID stored in %s\n", pidfile);
		} else {
			log_server_warning("Server running without PID file.\n");
		}
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
		sa.sa_flags = 0;
		pthread_sigmask(SIG_BLOCK, &sa.sa_mask, NULL);

		/* Run event loop. */
		for(;;) {
			pthread_sigmask(SIG_UNBLOCK, &sa.sa_mask, NULL);
			int ret = evqueue_poll(evqueue(), 0, 0);
			pthread_sigmask(SIG_BLOCK, &sa.sa_mask, NULL);

			/* Interrupts. */
			/*! \todo More robust way to exit evloop.
			 *        Event loop should exit with a special
			 *        event.
			 */
			if (sig_req_stop) {
				sig_req_stop = 0;
				server_stop(server);
				break;
			}
			if (sig_req_reload) {
				log_server_info("Reloading configuration...\n");
				sig_req_reload = 0;
				int cf_ret = cf_ret = conf_open(config_fn);
				switch (cf_ret) {
				case KNOTD_EOK:
					log_server_info("Configuration "
							"reloaded.\n");
					break;
				case KNOTD_ENOENT:
					log_server_error("Configuration "
							 "file '%s' "
							 "not found.\n",
							 conf()->filename);
					break;
				default:
					log_server_error("Configuration "
							 "reload failed.\n");
					break;
				}
			}

			/* Events. */
			if (ret > 0) {
				event_t ev;
				if (evqueue_get(evqueue(), &ev) == 0) {
					dbg_server_verb("Event: "
					                "received new event.\n");
					if (ev.cb) {
						ev.cb(&ev);
					}
				}
			}
		}
		pthread_sigmask(SIG_UNBLOCK, &sa.sa_mask, NULL);

		if ((res = server_wait(server)) != KNOTD_EOK) {
			log_server_error("An error occured while "
					 "waiting for server to finish.\n");
		} else {
			log_server_info("Server finished.\n");
		}

	} else {
		log_server_fatal("An error occured while "
				 "starting the server.\n");
	}

	// Stop server and close log
	server_destroy(&server);

	// Remove PID file
	if (pid_remove(pidfile) < 0) {
		log_server_warning("Failed to remove PID file.\n");
	}

	log_server_info("Shut down.\n");
	log_close();
	free(pidfile);

	// Destroy event loop
	evqueue_t *q = evqueue();
	evqueue_free(&q);

	// Free default config filename if exists
	free(config_fn);

	if (!daemonize) {
		fflush(stdout);
		fflush(stderr);
	}

	return res;
}
