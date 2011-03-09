#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "common.h"
#include "ctl/process.h"
#include "conf/conf.h"
#include "conf/logconf.h"
#include "dnslib/zone-load.h"

enum Constants {
	WAITPID_TIMEOUT = 10
};

void help(int argc, char **argv)
{
	printf("Usage: %s [parameters] start|stop|restart|reload|running|"
	       "compile\n",
	       argv[0]);
	printf("Parameters:\n"
	       " -c [file] Select configuration file.\n"
	       " -f\tForce operation - override some checks.\n"
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
	       " compile         Compile zone file.\n",
	       PROJECT_NAME, PROJECT_NAME, PROJECT_NAME, PROJECT_NAME);
}

int execute(const char *action, char **argv, int argc, pid_t pid, int verbose,
            int force)
{
	int valid_cmd = 0;
	int rc = 0;
	const char* pidfile = pid_filename();
	if (strcmp(action, "start") == 0) {

		// Check PID
		valid_cmd = 1;
		if (pid > 0 && pid_running(pid)) {

			fprintf(stderr, "control: Server PID found, "
			        "already running.\n");

			if (!force) {
				return 1;
			} else {
				fprintf(stderr, "control: forcing "
				        "server start.\n");
			}
		}

		// Prepare command
		const char *cfg = conf()->filename;
		char* cmd = 0;
		const char *cmd_str = "%s %s%s -d %s%s";
		rc = asprintf(&cmd, cmd_str, PROJECT_EXEC,
		              cfg ? "-c " : "", cfg ? cfg : "",
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
		rc = 0;
		if (pid <= 0 || !pid_running(pid)) {
			fprintf(stderr, "Server PID not found, "
			        "probably not running.\n");

			if (!force) {
				rc = 1;
			} else {
				fprintf(stderr, "control: forcing "
				        "server stop.\n");
			}
		}

		// Stop
		if (rc == 0) {
			if (kill(pid, SIGTERM) < 0) {
				pid_remove(pidfile);
				rc = 1;
			}
		}
	}
	if (strcmp(action, "restart") == 0) {
		valid_cmd = 1;
		execute("stop", argv, argc, pid, verbose, force);

		int i = 0;
		while((pid = pid_read(pidfile)) > 0) {

			if (!pid_running(pid)) {
				pid_remove(pidfile);
				break;
			}
			if (i == WAITPID_TIMEOUT) {
				fprintf(stderr, "Timeout while "
				        "waiting for the server to finish.\n");
				pid_remove(pidfile);
				break;
			} else {
				sleep(1);
				++i;
			}
		}

		printf("Restarting server.\n");
		rc = execute("start", argv, argc, -1, verbose, force);
	}
	if (strcmp(action, "reload") == 0) {

		// Check PID
		valid_cmd = 1;
		if (pid <= 0 || !pid_running(pid)) {
			fprintf(stderr, "Server PID not found, "
			        "probably not running.\n");

			if (force) {
				fprintf(stderr, "control: forcing "
				        "server stop.\n");
			} else {
				return 1;
			}
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
			if (!pid_running(pid)) {
				printf("Server PID not found, "
				       "probably not running.\n");
				fprintf(stderr,
				        "warning: PID file is stale.\n");
			} else {
				printf("Server running as PID %ld.\n",
				       (long)pid);
			}
			rc = 0;
		}
	}
	if (strcmp(action, "compile") == 0) {

		// Check zone
		valid_cmd = 1;

		// Generate databases for all zones
		node *n = 0;
		WALK_LIST(n, conf()->zones) {

			// Fetch zone
			conf_zone_t *zone = (conf_zone_t*)n;

			// Check source files and mtime
			zloader_t *zl = dnslib_zload_open(zone->db);
			if (!dnslib_zload_needs_update(zl)) {
				printf("Zone '%s' is up-to-date.\n",
				       zone->name);

				if (force) {
					fprintf(stderr, "control: forcing "
					        "zone recompilation.\n");
				} else {
					dnslib_zload_close(zl);
					continue;
				}
			}
			dnslib_zload_close(zl);

			// Prepare command
			char* cmd = 0;
			const char *cmd_str = "%s -o %s %s%s %s";
			rc = asprintf(&cmd, cmd_str, ZONEPARSER_EXEC,
			              zone->db, verbose ? "-v " : "",
			              zone->name, zone->file);

			// Execute command
			if (verbose) {
				printf("Compiling '%s'...\n",
				       zone->name);
			}
			if ((rc = system(cmd)) < 0) {
				rc = 1;
			}
			free(cmd);
		}
	}
	if (!valid_cmd) {
		fprintf(stderr, "Invalid command: '%s'\n", action);
		return 1;
	}

	// Log
	if (verbose) {
		printf("'%s' finished (return code %d)\n", action, rc);
	}
	return rc;
}

int main(int argc, char **argv)
{
	// Parse command line arguments
	int c = 0;
	int force = 0;
	int verbose = 0;
	const char* config_fn = 0;
	while ((c = getopt (argc, argv, "fc:vVh")) != -1) {
		switch (c)
		{
		case 'f':
			force = 1;
			break;
		case 'c':
			config_fn = optarg;
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

	// Initialize log (no output)
	log_init();

	// Find implicit configuration file
	char *default_fn = 0;
	if (!config_fn) {
		default_fn = conf_find_default();
		config_fn = default_fn;
	}

	// Open configuration
	if (conf_open(config_fn) != 0) {
		fprintf(stderr, "Failed to parse configuration '%s'.\n",
		        config_fn);
	}

	// Free default config filename if exists
	free(default_fn);

	// Verbose mode
	if (verbose) {
		int mask = LOG_MASK(LOG_INFO)|LOG_MASK(LOG_DEBUG);
		log_levels_add(LOGT_STDOUT, LOG_ANY, mask);
	}

	// Fetch PID
	const char* pidfile = pid_filename();
	if (!pidfile) {
		fprintf(stderr, "No configuration found, "
		        "please specify with '-c' parameter.\n");
		log_close();
		return 1;
	}

	pid_t pid = pid_read(pidfile);

	// Actions
	const char* action = argv[optind];

	// Execute action
	int rc = execute(action, argv + optind + 1, argc - optind - 1,
			 pid, verbose, force);

	// Finish
	log_close();
	return rc;
}
