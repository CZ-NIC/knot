#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "server.h"
#include "zoneparser.h"

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
		log_info("TODO: reload configuration...\n");
		/// \todo Reload configuration?
	}

	// Stop server
	if (s == SIGINT || s == SIGTERM) {
		if (s_stopping == 0) {
			s_stopping = 1;
			cute_stop(s_server);
		} else {
			log_error("\nOK! OK! Exiting immediately.\n");
			exit(1);
		}
	}
}

void help(int argc, char **argv)
{
	printf("Usage: %s [parameters] <filename1> [<filename2> ...]\n",
	       argv[0]);
	printf("Parameters:\n"
	       " -d\tRun server as a daemon.\n"
	       " -v\tVerbose mode - additional runtime information.\n"
	       " -V\tPrint version of the server.\n"
	       " -h\tPrint help and usage.\n");
}

int main(int argc, char **argv)
{
	// Parse command line arguments
	int c = 0;
	int verbose = 0;
	int daemonize = 0;
	while ((c = getopt (argc, argv, "dvVh")) != -1) {
		switch (c)
		{
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

	// Check if there's at least one remaining non-option
	if (argc - optind < 1) {
		help(argc, argv);
		return 1;
	}

	// Now check if we want to daemonize
	if (daemonize) {
		if (daemon(1, 0) != 0) {
			log_open(0, LOG_MASK(LOG_ERR));
			log_error("Daemonization failed, shutting down...\n");
			log_close();
			return 1;
		}
	}

	// Open log
	int log_mask = LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING);
	int print_mask = LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING);
	if (verbose) {
		print_mask |= LOG_MASK(LOG_NOTICE);
		print_mask |= LOG_MASK(LOG_INFO);
		log_mask = print_mask;
	}

	log_open(print_mask, log_mask);

	// Create server instance
	s_server = cute_create();

	// Run server
	int res = 0;
	if ((res = cute_start(s_server, argv + optind, argc - optind)) == 0) {

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
		log_info("Server started.\n");
		if (daemonize) {
			res = chdir("/");
		}

		if ((res = cute_wait(s_server)) != 0) {
			log_error("There was an error while waiting for server"
			          " to finish.\n");
		}
	} else {
		log_error("There was an error while starting the server, "
		          "exiting...\n");
	}

	// Stop server and close log
	cute_destroy(&s_server);
	log_info("Shutting down...\n");
	log_close();

	return res;
}
