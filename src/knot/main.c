#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "knot/common.h"
#include "knot/other/error.h"
#include "knot/server/server.h"
#include "zcompile/zcompile.h"
#include "knot/ctl/process.h"
#include "knot/conf/conf.h"
#include "knot/conf/logconf.h"
#include "common/evqueue.h"

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
			log_server_error("\nOK! Exiting immediately.\n");
			exit(1);
		}
	}
}

void help(int argc, char **argv)
{
	printf("Usage: %s [parameters]\n",
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
	char* config_fn = 0;
	while ((c = getopt (argc, argv, "c:dvVh")) != -1) {
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
			printf("%s, version %d.%d.%d\n", PROJECT_NAME,
			       PROJECT_VER >> 16 & 0x000000ff,
			       PROJECT_VER >> 8 & 0x000000ff,
			       PROJECT_VER >> 0 & 0x000000ff);
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
	conf_add_hook(conf(), CONF_LOG, ns_conf_hook, server->nameserver);
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
		char *cwbuf = malloc((cwbuflen + 1) * sizeof(char));
		while (getcwd(cwbuf, cwbuflen) == 0) {
			cwbuflen += 64;
			cwbuf = realloc(cwbuf, (cwbuflen + 1) * sizeof(char));
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
	if (conf_open(config_fn) != KNOT_EOK) {

		log_server_error("Failed to parse configuration file '%s'.\n",
				 config_fn);

		log_server_warning("No zone served.\n");
	} else {
		log_server_info("Configured %d interfaces and %d zones.\n",
				conf()->ifaces_count, conf()->zones_count);
	}
	log_server_info("\n");

	// Setup signal blocking
	struct sigaction sa_empty;
	sa_empty.sa_flags = 0;
	sa_empty.sa_handler = interrupt_handle;
	sigemptyset(&sa_empty.sa_mask);
	sigaction(SIGALRM, &sa_empty, 0); // Use for interrupting I/O
	pthread_sigmask(SIG_BLOCK, &sa_empty.sa_mask, NULL);

	// Create server instance
	char* pidfile = pid_filename();

	// Run server
	int res = 0;
	log_server_info("Starting server...\n");
	if ((res = server_start(server)) == KNOT_EOK) {

		// Save PID
		int rc = pid_write(pidfile);
		if (rc < 0) {
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
		log_server_info("PID stored in %s\n", pidfile);

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
			int ret = evqueue_poll(evqueue(), 0, &sa_empty.sa_mask);

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
				case KNOT_EOK:
					log_server_info("Configuration "
							"reloaded.\n");
					break;
				case KNOT_ENOENT:
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
					debug_server("Event: "
						     "received new event.\n");
					if (ev.cb) {
						ev.cb(&ev);
					}
				}
			}
		}

		if ((res = server_wait(server)) != KNOT_EOK) {
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

	return res;
}
