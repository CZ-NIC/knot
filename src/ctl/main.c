#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"

void help(int argc, char **argv)
{
	printf("Usage: %s [parameters] start|stop|restart|reload\n",
	       argv[0]);
	printf("Parameters:\n"
	       " -v\tVerbose mode - additional runtime information.\n"
	       " -V\tPrint %s server version.\n"
	       " -h\tPrint help and usage.\n",
	       PROJECT_NAME);
	printf("Actions:\n"
	       " start   Start %s server (no-op if running).\n"
	       " stop    Stop %s server (no-on if not running).\n"
	       " restart Stops and then starts %s server.\n"
	       " reload  Reload %s configuration and zone files.\n",
	       PROJECT_NAME, PROJECT_NAME, PROJECT_NAME, PROJECT_NAME);
}

int main(int argc, char **argv)
{
	// Parse command line arguments
	int c = 0;
	int verbose = 0;
	while ((c = getopt (argc, argv, "vVh")) != -1) {
		switch (c)
		{
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

	// Open log
	int log_mask = LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING);
	int print_mask = LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING);
	if (verbose) {
		print_mask |= LOG_MASK(LOG_NOTICE);
		print_mask |= LOG_MASK(LOG_INFO);
		log_mask = print_mask;
	}

	log_open(print_mask, log_mask);

	// Actions


	// Finish
	log_close();
	return 0;
}
