#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "server.h"
#include "zoneparser.h"
#include "process.h"
#include "conf/conf.h"
#include "conf/logconf.h"

/*----------------------------------------------------------------------------*/

static volatile short s_stopping = 0;
static cute_server *s_server = NULL;

// SIGINT signal handler
void interrupt_handle(int s)
{
	// Omit other signals
	if (s_server == NULL) {
		return;
	}

	// Reload configuration
	if (s == SIGHUP) {
		log_server_info("server: fixme: reload configuration.\n");
		/// \todo Reload configuration?
	}

	// Stop server
	if (s == SIGINT || s == SIGTERM) {
		if (s_stopping == 0) {
			s_stopping = 1;
			cute_stop(s_server);
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

	// Initialize log
	log_init();

	// Check if there's at least one remaining non-option
	int zfs_count = argc - optind;
	const char **zfs = (const char**)argv + optind;

	// Now check if we want to daemonize
	if (daemonize) {
		if (daemon(1, 0) != 0) {
			log_server_error("Daemonization failed, shutting down...\n");
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
			log_server_error("server: No zone files specified, "
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

	// Save PID
	const char* pidfile = pid_filename();
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



	// Create server instance
	s_server = cute_create();

	// Run server
	int res = 0;
	if ((res = cute_start(s_server, zfs, zfs_count)) == 0) {

		// Register service and signal handler
		struct sigaction sa;
		sa.sa_handler = interrupt_handle;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sigaction(SIGINT,  &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
		sigaction(SIGHUP,  &sa, NULL);
		sigaction(SIGALRM, &sa, NULL); // Interrupt

		// Change directory if daemonized
		log_server_info("server: Started.\n");
		if (daemonize) {
			log_server_info("Server running as daemon.\n");
			res = chdir("/");
		}

		if ((res = cute_wait(s_server)) != 0) {
			log_server_error("server: An error occured while "
			                 "waiting for server to finish.\n");
		}
	} else {
		log_server_error("server: An error occured while "
		                 "starting the server.\n");
	}

	// Stop server and close log
	cute_destroy(&s_server);

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

	return res;
}
