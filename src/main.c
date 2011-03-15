#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "server/server.h"
#include "zoneparser/zoneparser.h"
#include "ctl/process.h"
#include "conf/conf.h"
#include "conf/logconf.h"
#include "lib/evqueue.h"

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
			log_server_error("server: \nOK! OK! Exiting immediately.\n");
			exit(1);
		}
	}
}

void help(int argc, char **argv)
{
	printf("Usage: %s [parameters] [<filename1> <filename2> ...]\n",
	       argv[0]);
	printf("Parameters:\n"
	       " -c [file] Select configuration file.\n"
	       " -d        Run server as a daemon.\n"
	       " -v        Verbose mode - additional runtime information.\n"
	       " -V        Print version of the server.\n"
	       " -h        Print help and usage.\n");
}

int main(int argc, char **argv)
{
	// Parse command line arguments
	int c = 0;
	int verbose = 0;
	int daemonize = 0;
	const char* config_fn = 0;
	while ((c = getopt (argc, argv, "c:dvVh")) != -1) {
		switch (c)
		{
		case 'c':
			config_fn = optarg;
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'V':
			printf("%s, version %d.%d.%d\n", PROJECT_NAME,
			       PROJECT_VER >> 16 & 0x000000ff,
			       PROJECT_VER >> 8 & 0x000000ff,
			       PROJECT_VER >> 0 & 0x000000ff);
			return 1;
		case 'h':
		case '?':
		default:
			help(argc, argv);
			return 1;
		}
	}

	// Setup event queue
	evqueue_set(evqueue_new());

	// Initialize log
	log_init();

	// Check if there's at least one remaining non-option
	int zfs_count = argc - optind;
	const char **zfs = (const char**)argv + optind;

	// Now check if we want to daemonize
	if (daemonize) {
		if (daemon(1, 0) != 0) {
			log_server_fatal("Daemonization failed, shutting down...\n");
			log_close();
			return 1;
		}
	}

	// Initialize configuration
	conf_add_hook(conf(), CONF_LOG, log_conf_hook);

	// Find implicit configuration file
	char *default_fn = 0;
	if (!config_fn) {
		default_fn = conf_find_default();
		config_fn = default_fn;
	}

	// Open configuration
	if (conf_open(config_fn) != 0) {

		log_server_error("server: Failed to parse configuration '%s'.\n"
		                 , config_fn);

		if (zfs_count < 1) {
			log_server_fatal("server: No zone files specified, "
			                 "shutting down.\n\n");
			help(argc, argv);
			log_close();
			free(default_fn);
			return 1;
		}
	}

	// Free default config filename if exists
	free(default_fn);

	// Verbose mode
	if (verbose) {
		int mask = LOG_MASK(LOG_INFO)|LOG_MASK(LOG_DEBUG);
		log_levels_add(LOGT_STDOUT, LOG_ANY, mask);
	}

	// Create server instance
	const char* pidfile = pid_filename();
	server_t *server = server_create();

	// Run server
	int res = 0;
	if ((res = server_start(server, zfs, zfs_count)) == 0) {

		// Save PID
		if (daemonize) {
			int rc = pid_write(pidfile);
			if (rc < 0) {
				log_server_warning("server: Failed to create PID "
				                   "file '%s'.",
				                   pidfile);
			} else {
				log_server_info("server: PID file '%s' created.",
				                pidfile);
			}
		}

		// Setup signal blocking
		sigset_t emptyset, blockset;
		sigemptyset(&emptyset);
		sigemptyset(&blockset);
		sigaddset(&blockset, SIGINT);
		sigaddset(&blockset, SIGTERM);
		sigaddset(&blockset, SIGHUP);
		sigaddset(&blockset, SIGALRM); // Interrupt
		sigprocmask(SIG_BLOCK, &blockset, NULL);

		// Setup signal handler
		struct sigaction sa;
		sa.sa_handler = interrupt_handle;
		sigemptyset(&sa.sa_mask);
		sigaction(SIGINT,  &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
		sigaction(SIGHUP,  &sa, NULL);
		sigaction(SIGALRM, &sa, NULL); // Interrupt
		sa.sa_flags = 0;

		// Change directory if daemonized
		log_server_info("server: Started.\n");
		if (daemonize) {
			log_server_info("Server running as daemon.\n");
			res = chdir("/");
		}

		/* Run event loop. */
		for(;;) {
			int ret = evqueue_poll(evqueue(), &emptyset);

			/* Interrupts. */
			if (ret == -1) {
				/*! \todo More robust way to exit evloop.
				 *        Event loop should exit with a special
				 *        event.
				 */
				if (sig_req_stop) {
					debug_server("evqueue:"
					             "server stop requested\n");
					sig_req_stop = 0;
					server_stop(server);
					break;
				}
				if (sig_req_reload) {
					debug_server("evqueue:"
					             "reloading config\n");
					sig_req_reload = 0;
					//! \todo Reload config.
				}
			}

			/* Events. */
			if (ret > 0) {
				event_t ev;
				if (evqueue_get(evqueue(), &ev) == 0) {
					debug_server("evqueue:"
					             "received new event\n");
					if (ev.cb) {
						ev.cb(&ev);
					}
				}
			}

		}

		if ((res = server_wait(server)) != 0) {
			log_server_error("server: An error occured while "
			                 "waiting for server to finish.\n");
		}

	} else {
		log_server_fatal("server: An error occured while "
		                 "starting the server.\n");
	}

	// Stop server and close log
	server_destroy(&server);

	// Remove PID file if daemonized
	if (daemonize) {
		if (pid_remove(pidfile) < 0) {
			log_server_warning("server: Failed to remove "
			                   "PID file.\n");
		} else {
			log_server_info("server: PID file safely removed.\n");
		}
	}

	log_server_info("server: Shut down.\n");
	log_close();

	// Destroy event loop
	evqueue_t *q = evqueue();
	evqueue_free(&q);

	return res;
}
