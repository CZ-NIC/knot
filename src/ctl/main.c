#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "common.h"
#include "process.h"

enum Constants {
	WAITPID_TIMEOUT = 10
};

void help(int argc, char **argv)
{
	printf("Usage: %s [parameters] start|stop|restart|reload|running|compile"
	       " [zone file]\n",
	       argv[0]);
	printf("Parameters:\n"
	       " -v\tVerbose mode - additional runtime information.\n"
	       " -V\tPrint %s server version.\n"
	       " -h\tPrint help and usage.\n",
	       PROJECT_NAME);
	printf("Actions:\n"
	       " start   [zone]  Start %s server with given zone (no-op if running).\n"
	       " stop            Stop %s server (no-op if not running).\n"
	       " restart [zone]  Stops and then starts %s server.\n"
	       " reload  [zone]  Reload %s configuration and zone files.\n"
	       " running         Check if server is running.\n"
	       "\n"
	       " compile <zone_name> <zone> Compile zone file.\n"
	       "                            <zone_name> should be a fully-"
	                                    "qualified domain name\n",
	       PROJECT_NAME, PROJECT_NAME, PROJECT_NAME, PROJECT_NAME);
}

int execute(const char *action, char **argv, int argc, pid_t pid, int verbose)
{
	int valid_cmd = 0;
	int rc = 0;
	char* pidfile = pid_filename();
	if (strcmp(action, "start") == 0) {

		// Check PID
		valid_cmd = 1;
		if (pid > 0) {
			log_info("Server PID found, already running.\n");
			free(pidfile);
			return 1;
		}

		// Prepare command
		char* cmd = 0;
		const char *cmd_str = "%s -d %s%s";
		rc = asprintf(&cmd, cmd_str, PROJECT_EXEC,
			      verbose ? "-v " : "", argc > 0 ? argv[0] : "");

		// Execute command
		if ((rc = system(cmd)) < 0) {
			pid_remove(pidfile);
			rc = 1;
		}
		free(cmd);

	}
	if (strcmp(action, "stop") == 0) {

		// Check PID
		valid_cmd = 1;
		if (pid <= 0) {
			log_info("Server PID not found, "
				 "probably not running.\n");
			rc = 1;
		} else {
			// Stop
			if (kill(pid, SIGTERM) < 0) {
				pid_remove(pidfile);
				rc = 1;
			}
		}
	}
	if (strcmp(action, "restart") == 0) {
		valid_cmd = 1;
		execute("stop", argv, argc, pid, verbose);

		int i = 0;
		while(pid_read(pidfile) > 0) {
			if (i == WAITPID_TIMEOUT) {
				log_warning("Timeout while waiting for server "
					    "to finish...\n");
				pid_remove(pidfile);
				break;
			} else {
				sleep(1);
				++i;
			}
		}

		rc = execute("start", argv, argc, -1, verbose);
	}
	if (strcmp(action, "reload") == 0) {

		// Check PID
		valid_cmd = 1;
		if (pid <= 0) {
			log_info("Server PID not found, "
				 "probably not running.\n");
			free(pidfile);
			return 1;
		}

		// Stop
		if (kill(pid, SIGHUP) < 0) {
			pid_remove(pidfile);
			rc = 1;
		}
	}
	if (strcmp(action, "running") == 0) {

		// Check PID
		valid_cmd = 1;
		if (pid <= 0) {
			printf("Server PID not found, "
			       "probably not running.\n");
			rc = 1;
		} else {
			printf("Server running as PID %ld.\n", (long)pid);
			rc = 0;
		}
	}
	if (strcmp(action, "compile") == 0) {

		// Check zone
		valid_cmd = 1;
		if (argc < 2) {
			log_error("Zone file or zone name not specified.\n");
			free(pidfile);
			return 1;
		}

		// Prepare command
		char* cmd = 0;
		const char *cmd_str = "%s %s%s %s";
		rc = asprintf(&cmd, cmd_str, ZONEPARSER_EXEC,
			      verbose ? "-v " : "", argv[0], argv[1]);

		// Execute command
		if ((rc = system(cmd)) < 0) {
			rc = 1;
		}
		free(cmd);
	}
	if (!valid_cmd) {
		log_error("Invalid command: '%s'\n", action);
		free(pidfile);
		return 1;
	}

	// Log
	log_info("Server %s finished (return code %d)\n", action, rc);
	free(pidfile);
	return rc;
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

	log_init(print_mask, log_mask);

	// Fetch PID
	char* pidfile = pid_filename();
	pid_t pid = pid_read(pidfile);

	// Actions
	const char* action = argv[optind];

	// Execute action
	int rc = execute(action, argv + optind + 1, argc - optind - 1,
			 pid, verbose);

	// Finish
	free(pidfile);
	log_close();
	return rc;
}
