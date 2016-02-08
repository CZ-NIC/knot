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

#include <dirent.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <urcu.h>

#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "dnssec/crypto.h"
#include "libknot/libknot.h"
#include "knot/ctl/remote.h"
#include "knot/conf/conf.h"
#include "knot/common/log.h"
#include "knot/common/process.h"
#include "knot/server/server.h"
#include "knot/server/tcp-handler.h"
#include "knot/zone/timers.h"

#define PROGRAM_NAME "knotd"

/* Signal flags. */
static volatile bool sig_req_stop = false;
static volatile bool sig_req_reload = false;

/* \brief Signal started state to the init system. */
static void init_signal_started(void)
{
#ifdef ENABLE_SYSTEMD
	sd_notify(0, "READY=1");
#endif
}

static int make_daemon(int nochdir, int noclose)
{
	int fd, ret;

	switch (fork()) {
	case -1:
		/* Error */
		return -1;
	case 0:
		/* Forked */
		break;
	default:
		/* Exit the main process */
		_exit(0);
	}

	if (setsid() == -1) {
		return -1;
	}

	if (!nochdir) {
		ret = chdir("/");
		if (ret == -1)
			return errno;
	}

	if (!noclose) {
		ret  = close(STDIN_FILENO);
		ret += close(STDOUT_FILENO);
		ret += close(STDERR_FILENO);
		if (ret < 0) {
			return errno;
		}

		fd = open("/dev/null", O_RDWR);
		if (fd == -1) {
			return errno;
		}

		if (dup2(fd, STDIN_FILENO) < 0) {
			return errno;
		}
		if (dup2(fd, STDOUT_FILENO) < 0) {
			return errno;
		}
		if (dup2(fd, STDERR_FILENO) < 0) {
			return errno;
		}
	}

	return 0;
}

struct signal {
	int signum;
	bool handle;
};

/*! \brief Signals used by the server. */
static const struct signal SIGNALS[] = {
	{ SIGHUP,  true  },  /* Reload server. */
	{ SIGINT,  true  },  /* Terminate server .*/
	{ SIGTERM, true  },
	{ SIGALRM, false },  /* Internal thread synchronization. */
	{ SIGPIPE, false },  /* Ignored. Some I/O errors. */
	{ 0 }
};

/*! \brief Server signal handler. */
static void handle_signal(int signum)
{
	switch (signum) {
	case SIGHUP:
		sig_req_reload = true;
		break;
	case SIGINT:
	case SIGTERM:
		if (sig_req_stop) {
			abort();
		}
		sig_req_stop = true;
		break;
	default:
		/* ignore */
		break;
	}
}

/*! \brief Setup signal handlers and blocking mask. */
static void setup_signals(void)
{
	/* Block all signals. */
	static sigset_t all;
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, NULL);

	/* Setup handlers. */
	struct sigaction action = { .sa_handler = handle_signal };
	for (const struct signal *s = SIGNALS; s->signum > 0; s++) {
		sigaction(s->signum, &action, NULL);
	}
}

/*! \brief Unblock server control signals. */
static void enable_signals(void)
{
	sigset_t mask;
	sigemptyset(&mask);

	for (const struct signal *s = SIGNALS; s->signum > 0; s++) {
		if (s->handle) {
			sigaddset(&mask, s->signum);
		}
	}

	pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
}

/*! \brief POSIX 1003.1e capabilities. */
static void setup_capabilities(void)
{
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

		/* Apply. */
		if (capng_apply(CAPNG_SELECT_BOTH) < 0) {
			log_error("failed to set process capabilities (%s)",
			          strerror(errno));
		}
	} else {
		log_info("user UID %d is not allowed to set capabilities, "
		         "skipping", getuid());
	}
#endif /* HAVE_CAP_NG_H */
}

/*! \brief Event loop listening for signals and remote commands. */
static void event_loop(server_t *server, char *socket)
{
	uint8_t buf[KNOT_WIRE_MAX_PKTSIZE];
	size_t buflen = sizeof(buf);

	/* Get control socket configuration. */
	char *listen = socket;
	if (socket == NULL) {
		conf_val_t listen_val = conf_get(conf(), C_CTL, C_LISTEN);
		conf_val_t rundir_val = conf_get(conf(), C_SRV, C_RUNDIR);
		char *rundir = conf_abs_path(&rundir_val, NULL);
		listen = conf_abs_path(&listen_val, rundir);
		free(rundir);
	}

	/* Bind to control socket (error logging is inside the function. */
	int sock = remote_bind(listen);

	if (socket == NULL) {
		free(listen);
	}

	enable_signals();

	/* Run event loop. */
	for (;;) {
		/* Interrupts. */
		if (sig_req_stop) {
			break;
		}
		if (sig_req_reload) {
			sig_req_reload = false;
			server_reload(server, conf()->filename, true);
		}

		/* Control interface. */
		struct pollfd pfd = { .fd = sock, .events = POLLIN };
		int ret = poll(&pfd, 1, -1);
		if (ret > 0) {
			ret = remote_process(server, sock, buf, buflen);
			if (ret == KNOT_CTL_ESTOP) {
				break;
			}
		}
	}

	/* Close control socket. */
	remote_unbind(sock);
}

static void print_help(void)
{
	printf("Usage: %s [parameters]\n"
	       "\n"
	       "Parameters:\n"
	       " -c, --config <file>     Use a textual configuration file.\n"
	       "                           (default %s)\n"
	       " -C, --confdb <dir>      Use a binary configuration database directory.\n"
	       "                           (default %s)\n"
	       " -s, --socket <path>     Use a remote control UNIX socket path.\n"
	       "                           (default %s)\n"
	       " -d, --daemonize=[dir]   Run the server as a daemon (with new root directory).\n"
	       " -v, --verbose           Enable debug output.\n"
	       " -h, --help              Print the program help.\n"
	       " -V, --version           Print the program version.\n",
	       PROGRAM_NAME, CONF_DEFAULT_FILE, CONF_DEFAULT_DBDIR, RUN_DIR "/knot.sock");
}

static void print_version(void)
{
	printf("%s (Knot DNS), version %s\n", PROGRAM_NAME, PACKAGE_VERSION);
}

static int set_config(const char *confdb, const char *config)
{
	if (config != NULL && confdb != NULL) {
		log_fatal("ambiguous configuration source");
		return KNOT_EINVAL;
	}

	/* Choose the optimal config source. */
	struct stat st;
	bool import = false;
	if (confdb != NULL) {
		import = false;
	} else if (config != NULL){
		import = true;
	} else if (stat(CONF_DEFAULT_DBDIR, &st) == 0) {
		import = false;
		confdb = CONF_DEFAULT_DBDIR;
	} else {
		import = true;
		config = CONF_DEFAULT_FILE;
	}

	const char *src = import ? config : confdb;
	log_debug("%s '%s'", import ? "config" : "confdb",
	          (src != NULL) ? src : "empty");

	/* Open confdb. */
	conf_t *new_conf = NULL;
	int ret = conf_new(&new_conf, conf_scheme, confdb, CONF_FNONE);
	if (ret != KNOT_EOK) {
		log_fatal("failed to open configuration database '%s' (%s)",
		          (confdb != NULL) ? confdb : "", knot_strerror(ret));
		return ret;
	}

	/* Import the config file. */
	if (import) {
		ret = conf_import(new_conf, config, true);
		if (ret != KNOT_EOK) {
			log_fatal("failed to load configuration file '%s' (%s)",
			          config, knot_strerror(ret));
			conf_free(new_conf);
			return ret;
		}
	}

	/* Activate global query modules. */
	conf_activate_modules(new_conf, NULL, &new_conf->query_modules,
	                      &new_conf->query_plan);

	/* Update to the new config. */
	conf_update(new_conf);

	return KNOT_EOK;
}

int main(int argc, char **argv)
{
	bool daemonize = false;
	const char *config = NULL;
	const char *confdb = NULL;
	const char *daemon_root = "/";
	char *socket = NULL;
	bool verbose = false;

	/* Long options. */
	struct option opts[] = {
		{ "config",    required_argument, NULL, 'c' },
		{ "confdb",    required_argument, NULL, 'C' },
		{ "socket",    required_argument, NULL, 's' },
		{ "daemonize", optional_argument, NULL, 'd' },
		{ "verbose",   no_argument,       NULL, 'v' },
		{ "help",      no_argument,       NULL, 'h' },
		{ "version",   no_argument,       NULL, 'V' },
		{ NULL }
	};

	/* Parse command line arguments. */
	int opt = 0, li = 0;
	while ((opt = getopt_long(argc, argv, "c:C:s:dvhV", opts, &li)) != -1) {
		switch (opt) {
		case 'c':
			config = optarg;
			break;
		case 'C':
			confdb = optarg;
			break;
		case 's':
			socket = optarg;
			break;
		case 'd':
			daemonize = true;
			if (optarg) {
				daemon_root = optarg;
			}
			break;
		case 'v':
			verbose = true;
			break;
		case 'h':
			print_help();
			return EXIT_SUCCESS;
		case 'V':
			print_version();
			return EXIT_SUCCESS;
		default:
			print_help();
			return EXIT_FAILURE;
		}
	}

	/* Check for non-option parameters. */
	if (argc - optind > 0) {
		print_help();
		return EXIT_FAILURE;
	}

	/* Set file creation mask to remove all permissions for others. */
	umask(S_IROTH|S_IWOTH|S_IXOTH);

	/* Now check if we want to daemonize. */
	if (daemonize) {
		if (make_daemon(1, 0) != 0) {
			fprintf(stderr, "Daemonization failed, shutting down...\n");
			return EXIT_FAILURE;
		}
	}

	/* Setup base signal handling. */
	setup_signals();

	/* Initialize cryptographic backend. */
	dnssec_crypto_init();
	atexit(dnssec_crypto_cleanup);

	/* Initialize pseudorandom number generator. */
	srand(time(NULL));

	/* POSIX 1003.1e capabilities. */
	setup_capabilities();

	/* Initialize logging subsystem. */
	log_init();
	if (verbose) {
		log_levels_add(LOGT_STDOUT, LOG_ANY, LOG_MASK(LOG_DEBUG));
	}

	/* Set up the configuration */
	int ret = set_config(confdb, config);
	if (ret != KNOT_EOK) {
		log_close();
		return EXIT_FAILURE;
	}

	/* Reconfigure logging. */
	log_reconfigure(conf());

	/* Initialize server. */
	server_t server;
	ret = server_init(&server, conf_bg_threads(conf()));
	if (ret != KNOT_EOK) {
		log_fatal("failed to initialize server (%s)", knot_strerror(ret));
		conf_free(conf());
		log_close();
		return EXIT_FAILURE;
	}

	/* Reconfigure server interfaces.
	 * @note This MUST be done before we drop privileges. */
	server_reconfigure(conf(), &server);

	/* Alter privileges. */
	int uid, gid;
	if (conf_user(conf(), &uid, &gid) != KNOT_EOK ||
	    log_update_privileges(uid, gid) != KNOT_EOK ||
	    proc_update_privileges(uid, gid) != KNOT_EOK) {
		log_fatal("failed to drop privileges");
		server_wait(&server);
		server_deinit(&server);
		conf_free(conf());
		log_close();
		return EXIT_FAILURE;
	}

	/* Check and create PID file. */
	long pid = (long)getpid();
	if (daemonize) {
		char *pidfile = pid_check_and_create();
		if (pidfile == NULL) {
			server_wait(&server);
			server_deinit(&server);
			conf_free(conf());
			log_close();
			return EXIT_FAILURE;
		}

		log_info("PID stored in '%s'", pidfile);
		free(pidfile);
		if (chdir(daemon_root) != 0) {
			log_warning("failed to change working directory to %s",
			            daemon_root);
		} else {
			log_info("changed directory to %s", daemon_root);
		}
	}

	/* Now we're going multithreaded. */
	rcu_register_thread();

	/* Populate zone database. */
	log_info("loading %zu zones", conf_id_count(conf(), C_ZONE));
	server_update_zones(conf(), &server);

	/* Check number of loaded zones. */
	if (knot_zonedb_size(server.zone_db) == 0) {
		log_warning("no zones loaded");
	}

	/* Start it up. */
	log_info("starting server");
	conf_val_t async_val = conf_get(conf(), C_SRV, C_ASYNC_START);
	ret = server_start(&server, conf_bool(&async_val));
	if (ret != KNOT_EOK) {
		log_fatal("failed to start server (%s)", knot_strerror(ret));
		server_wait(&server);
		server_deinit(&server);
		rcu_unregister_thread();
		pid_cleanup();
		log_close();
		conf_free(conf());
		return EXIT_FAILURE;
	}

	if (daemonize) {
		log_info("server started as a daemon, PID %ld", pid);
	} else {
		log_info("server started in the foreground, PID %ld", pid);
		init_signal_started();
	}

	/* Start the event loop. */
	event_loop(&server, socket);

	/* Teardown server. */
	server_stop(&server);
	server_wait(&server);

	log_info("updating zone timers database");
	write_timer_db(server.timers_db, server.zone_db);

	/* Cleanup PID file. */
	pid_cleanup();

	/* Free server and configuration. */
	server_deinit(&server);
	conf_free(conf());

	/* Unhook from RCU. */
	rcu_unregister_thread();

	log_info("shutting down");
	log_close();

	return EXIT_SUCCESS;
}
