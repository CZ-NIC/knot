/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/stat.h>
#include <urcu.h>

#ifdef ENABLE_CAP_NG
#include <cap-ng.h>
#endif

#include "libdnssec/crypto.h"
#include "libknot/libknot.h"
#include "contrib/strtonum.h"
#include "contrib/threads.h"
#include "contrib/time.h"
#include "knot/ctl/threads.h"
#include "knot/conf/conf.h"
#include "knot/conf/migration.h"
#include "knot/conf/module.h"
#include "knot/common/dbus.h"
#include "knot/common/log.h"
#include "knot/common/process.h"
#include "knot/common/stats.h"
#include "knot/common/systemd.h"
#include "knot/server/server.h"
#include "knot/server/signals.h"
#include "knot/server/tcp-handler.h"
#include "utils/common/params.h"

#define PROGRAM_NAME "knotd"

typedef struct {
	bool            first_loop;
	struct timespec loop_wait;
} startup_data_t;

static int make_daemon(int nochdir, int noclose)
{
	int ret;

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

		int fd = open("/dev/null", O_RDWR);
		if (fd == -1) {
			return errno;
		}

		if (dup2(fd, STDIN_FILENO) < 0) {
			close(fd);
			return errno;
		}
		if (dup2(fd, STDOUT_FILENO) < 0) {
			close(fd);
			return errno;
		}
		if (dup2(fd, STDERR_FILENO) < 0) {
			close(fd);
			return errno;
		}
		close(fd);
	}

	return 0;
}

/*! \brief Drop POSIX 1003.1e capabilities. */
static void drop_capabilities(void)
{
#ifdef ENABLE_CAP_NG
	/* Drop all capabilities. */
	if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
		capng_clear(CAPNG_SELECT_BOTH);

		/* Apply. */
		if (capng_apply(CAPNG_SELECT_BOTH) < 0) {
			log_error("failed to set process capabilities (%s)",
			          strerror(errno));
		}
	} else {
		log_info("process not allowed to set capabilities, skipping");
	}
#endif /* ENABLE_CAP_NG */
}

#define LOOP_WAIT            5   /* Seconds. It could be even infinity. */
#define LOOP_WAIT_MIN_MS   200   /* In milliseconds; it must be < 1000. */
#define LOOP_WAIT_MAX       30   /* Seconds. */
#define LOOP_WAIT_LOAD_MAX  10   /* Seconds. Can be overruled by higher initial wait value. */
#define LOAD_START_DECLINE  60   /* Seconds. Before the wait starts to grow. */

/*! \brief Calculate wait in 'started' state detection. */
static void calc_wait(startup_data_t *startup_data, struct timespec t)
{
	struct timespec rv;
	long int double_ns = 2 * t.tv_nsec;
	rv.tv_sec = 2 * t.tv_sec + double_ns / (1000 * 1000 * 1000L);
	rv.tv_nsec = double_ns % (1000 * 1000 * 1000L);
	if (rv.tv_sec == 0) {
		rv.tv_nsec = MAX(rv.tv_nsec, LOOP_WAIT_MIN_MS * 1000 * 1000L);
	} else {
		rv.tv_sec = MIN(rv.tv_sec, LOOP_WAIT_MAX);
	}

	startup_data->loop_wait = rv;
}

/*! \brief Calculate wait in 'loaded' state detection. */
static void calc_wait_loaded(startup_data_t *startup_data, struct timespec t)
{
	struct timespec wait = startup_data->loop_wait;
	assert(wait.tv_sec < LONG_MAX / 10000);

	if (wait.tv_sec >= LOOP_WAIT_LOAD_MAX) {  /* One second tolerance is ok. */
		return;
	}

	if (t.tv_sec < LOAD_START_DECLINE) {
		if (wait.tv_sec < 1) {   /* Start at one second at least. */
			startup_data->loop_wait.tv_sec = 1;
			startup_data->loop_wait.tv_nsec = 0;
		}
		return;
	}

	/* Multiply wait by approx. 1.05 -- just a chosen number. */
	long int waitm = wait.tv_sec * 1000 + wait.tv_nsec / (1000 * 1000);
	waitm *= 105;
	startup_data->loop_wait.tv_sec = waitm / (100 * 1000);
	startup_data->loop_wait.tv_nsec = (waitm % (100 * 1000)) * (10 * 1000);

	if (startup_data->loop_wait.tv_sec >= LOOP_WAIT_LOAD_MAX) {
		startup_data->loop_wait.tv_sec = LOOP_WAIT_LOAD_MAX;
		startup_data->loop_wait.tv_nsec = 0;
	}
}

static void reset_loop_wait(startup_data_t *startup_data)
{
	startup_data->loop_wait.tv_sec = LOOP_WAIT;
	startup_data->loop_wait.tv_nsec = 0;
}

static void walk_zonedb(server_t *server, bool *start, bool *load, bool started, bool fast)
{
	rcu_read_lock();
	knot_zonedb_iter_t *it = knot_zonedb_iter_begin(server->zone_db);
	while (!knot_zonedb_iter_finished(it)) {
		zone_t *zone = (zone_t *)knot_zonedb_iter_val(it);
		if (zone->contents == NULL) {
			*load = false;
			if (started && fast) {
				break;
			} else if (!zone->started) {
				*start = false;
				if (fast) {
					break;
				}
			}
		}
		knot_zonedb_iter_next(it);
	}
	knot_zonedb_iter_free(it);
	rcu_read_unlock();
}

static int check_loaded(server_t *server, bool async, startup_data_t *startup_data)
{
	/*
	 * Started: all zones loaded or at least tried to load at least once,
	 *          the server is already running and accepting queries.
	 * Loaded:  all zones successfully loaded, it implies 'started',
	 *          KNOT_BUS_EVENT_STARTED already emitted over DBus.
	 */
	static bool started = false;
	static bool loaded = false;
	static struct timespec started_time = { 0 };
	assert(server->state & ServerRunning);
	if (loaded) {
		assert(server->state & ServerAnswering);
		return KNOT_EOK;
	}

	/* Avoid traversing the zonedb too frequently. */
	static struct timespec last = { 0 };
	struct timespec now = time_now();
	if (last.tv_sec == now.tv_sec) {
		return KNOT_EOK;
	}
	last = now;

	started = started || async;
	bool start = true;
	bool load = true;

	/* In the first loop, benchmark the zonedb traversal while checking. */
	walk_zonedb(server, &start, &load, started, !startup_data->first_loop);

	if (startup_data->first_loop) {
		struct timespec then = time_now();
		calc_wait(startup_data, time_diff(&now, &then));
		startup_data->first_loop = false;
	}

	if (!start) {
		return KNOT_EOK;
	}
	if (!started) {
		int ret = server_start_answering(server);
		if (ret != KNOT_EOK) {
			return ret;
		}
		started = true;
		started_time = now;
	}

	assert(server->state & ServerAnswering);
	if (!(conf()->cache.srv_dbus_event & DBUS_EVENT_RUNNING)) {
		loaded = true;
		return KNOT_EOK;
	}

	if (load) {   /* Not 'loaded' yet. */
		dbus_emit_running(true);
		loaded = true;
		reset_loop_wait(startup_data);
	} else {
		/* Extend the wait gradually. */
		calc_wait_loaded(startup_data, time_diff(&started_time, &now));
	}

	return KNOT_EOK;
}

static void deinit_ctls(knot_ctl_t **ctls, unsigned count)
{
	for (unsigned i = 0; i < count; i++) {
		knot_ctl_unbind(ctls[i]);
		knot_ctl_free(ctls[i]);
	}
	free(ctls);
}

static unsigned count_ctls(const char *socket, conf_val_t *listen_val)
{
	return (socket == NULL) ? MAX(1, conf_val_count(listen_val)) : 1;
}

static knot_ctl_t **init_ctls(const char *socket)
{
	conf_val_t listen_val = conf_get(conf(), C_CTL, C_LISTEN);
	unsigned cnt = count_ctls(socket, &listen_val);

	knot_ctl_t **res = calloc(cnt, sizeof(*res));
	for (unsigned i = 0; i < cnt; i++) {
		res[i] = knot_ctl_alloc();
		if (res[i] == NULL) {
			log_fatal("control, failed to initialize socket");
			deinit_ctls(res, i);
			return NULL;
		}
	}

	uint16_t backlog = conf_get_int(conf(), C_CTL, C_BACKLOG);
	conf_val_t rundir_val = conf_get(conf(), C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&rundir_val, NULL);

	int ret = KNOT_EOK;
	for (unsigned i = 0; i < cnt && ret == KNOT_EOK; i++) {
		char *listen = (socket == NULL) ? conf_abs_path(&listen_val, rundir)
		                                : strdup(socket);
		if (listen == NULL) {
			log_fatal("control, empty socket path");
			ret = KNOT_ENOENT;
		} else {
			knot_ctl_set_timeout(res[i], conf()->cache.ctl_timeout);
			log_info("control, binding to '%s'", listen);
			ret = knot_ctl_bind(res[i], listen, backlog);
			if (ret != KNOT_EOK) {
				log_fatal("control, failed to bind socket '%s' (%s)",
				          listen, knot_strerror(ret));
			}
			free(listen);
		}
		if (cnt > 1) {
			conf_val_next(&listen_val);
		}
	}
	if (ret != KNOT_EOK) {
		deinit_ctls(res, cnt);
		res = NULL;
	}
	free(rundir);

	return res;
}

/*! \brief Event loop listening for signals and remote commands. */
static int event_loop(server_t *server, const char *socket, bool daemonize,
                      unsigned long pid, bool async)
{
	knot_ctl_t **ctls = init_ctls(socket);
	if (ctls == NULL) {
		return KNOT_ERROR;
	}

	conf_val_t listen_val = conf_get(conf(), C_CTL, C_LISTEN);
	unsigned sock_count = count_ctls(socket, &listen_val);
	ctl_socket_ctx_t sctx = {
		.ctls = ctls,
		.server = server,
		.thr_count = CTL_MAX_CONCURRENT / sock_count
	};

	int ret = ctl_socket_thr_init(&sctx, sock_count);
	if (ret != KNOT_EOK) {
		log_fatal("control, failed to launch socket threads (%s)",
		          knot_strerror(ret));
		return ret;
	}

	signals_enable();

	/* Notify systemd about successful start. */
	systemd_ready_notify();
	if (daemonize) {
		log_info("starting server as a daemon, PID %lu", pid);
	} else {
		log_info("starting server in the foreground, PID %lu", pid);
	}

	/* Server startup parameters. */
	startup_data_t startup_data = {
		.first_loop = true
	};

	/* Run interrupt processing loop. */
	for (;;) {
		if (signals_req_reload && !signals_req_stop) {
			signals_req_reload = false;
			pthread_rwlock_wrlock(&server->ctl_lock);
			server_reload(server, RELOAD_FULL);
			pthread_rwlock_unlock(&server->ctl_lock);
		}
		if (signals_req_zones_reload && !signals_req_stop) {
			signals_req_zones_reload = false;
			reload_t mode = ATOMIC_GET(server->catalog_upd_signal) ?
			                RELOAD_CATALOG : RELOAD_FULL;
			pthread_rwlock_wrlock(&server->ctl_lock);
			ATOMIC_SET(server->catalog_upd_signal, false);
			server_update_zones(conf(), server, mode);
			pthread_rwlock_unlock(&server->ctl_lock);
		}
		if (signals_req_stop) {
			break;
		}

		if (signals_req_reload || signals_req_zones_reload) {
			continue;
		}

		ret = check_loaded(server, async, &startup_data);
		if (ret != KNOT_EOK) {
			goto done;
		}

		/* Wait for signals to arrive. */
		nanosleep(&(startup_data.loop_wait), NULL);
	}

	if (conf()->cache.srv_dbus_event & DBUS_EVENT_RUNNING) {
		dbus_emit_running(false);
	}

done:
	ctl_socket_thr_end(&sctx);
	deinit_ctls(ctls, sock_count);
	return ret;
}

static void print_help(void)
{
	printf("Usage: %s [-c | -C <path>] [options]\n"
	       "\n"
	       "Config options:\n"
	       " -c, --config <file>        Use a textual configuration file.\n"
	       "                             (default %s)\n"
	       " -C, --confdb <dir>         Use a binary configuration database directory.\n"
	       "                             (default %s)\n"
	       "Options:\n"
	       " -m, --max-conf-size <MiB>  Set maximum size of the configuration database (max 10000 MiB).\n"
	       "                             (default %d MiB)\n"
	       " -s, --socket <path>        Use a remote control UNIX socket path.\n"
	       "                             (default %s)\n"
	       " -d, --daemonize=[dir]      Run the server as a daemon (with new root directory).\n"
	       " -v, --verbose              Enable debug output.\n"
	       " -h, --help                 Print the program help.\n"
	       " -V, --version              Print the program version.\n",
	       PROGRAM_NAME, CONF_DEFAULT_FILE, CONF_DEFAULT_DBDIR,
	       CONF_MAPSIZE, RUN_DIR "/knot.sock");
}

static int set_config(const char *confdb, const char *config, size_t max_conf_size)
{
	if (config != NULL && confdb != NULL) {
		log_fatal("ambiguous configuration source");
		return KNOT_EINVAL;
	}

	/* Choose the optimal config source. */
	bool import = false;
	if (confdb != NULL) {
		import = false;
	} else if (config != NULL){
		import = true;
	} else if (conf_db_exists(CONF_DEFAULT_DBDIR)) {
		import = false;
		confdb = CONF_DEFAULT_DBDIR;
	} else {
		import = true;
		config = CONF_DEFAULT_FILE;
	}

	/* Open confdb. */
	conf_t *new_conf = NULL;
	int ret = conf_new(&new_conf, conf_schema, confdb, max_conf_size, CONF_FREQMODULES);
	if (ret != KNOT_EOK) {
		log_fatal("failed to open configuration database '%s' (%s)",
		          (confdb != NULL) ? confdb : "", knot_strerror(ret));
		return ret;
	}

	/* Import the config file. */
	if (import) {
		ret = conf_import(new_conf, config, IMPORT_FILE | IMPORT_REINIT_CACHE);
		if (ret != KNOT_EOK) {
			log_fatal("failed to load configuration file '%s' (%s)",
			          config, knot_strerror(ret));
			conf_free(new_conf);
			return ret;
		}
	}

	// Migrate from old schema.
	ret = conf_migrate(new_conf);
	if (ret != KNOT_EOK) {
		log_error("failed to migrate configuration (%s)", knot_strerror(ret));
	}

	/* Update to the new config. */
	conf_update(new_conf, CONF_UPD_FNONE);

	return KNOT_EOK;
}

int main(int argc, char **argv)
{
	bool daemonize = false;
	const char *config = NULL;
	const char *confdb = NULL;
	size_t max_conf_size = (size_t)CONF_MAPSIZE * 1024 * 1024;
	const char *daemon_root = "/";
	char *socket = NULL;
	bool verbose = false;

	/* Long options. */
	struct option opts[] = {
		{ "config",        required_argument, NULL, 'c' },
		{ "confdb",        required_argument, NULL, 'C' },
		{ "max-conf-size", required_argument, NULL, 'm' },
		{ "socket",        required_argument, NULL, 's' },
		{ "daemonize",     optional_argument, NULL, 'd' },
		{ "verbose",       no_argument,       NULL, 'v' },
		{ "help",          no_argument,       NULL, 'h' },
		{ "version",       optional_argument, NULL, 'V' },
		{ NULL }
	};

	/* Set the time zone. */
	tzset();

	/* Parse command line arguments. */
	int opt = 0;
	while ((opt = getopt_long(argc, argv, "c:C:m:s:dvhV::", opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			config = optarg;
			break;
		case 'C':
			confdb = optarg;
			break;
		case 'm':
			if (str_to_size(optarg, &max_conf_size, 1, 10000) != KNOT_EOK) {
				print_help();
				return EXIT_FAILURE;
			}
			/* Convert to bytes. */
			max_conf_size *= 1024 * 1024;
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
			print_version(PROGRAM_NAME, optarg != NULL);
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
	umask(S_IROTH | S_IWOTH | S_IXOTH);

	/* Now check if we want to daemonize. */
	if (daemonize) {
		if (make_daemon(1, 0) != 0) {
			fprintf(stderr, "Daemonization failed, shutting down...\n");
			return EXIT_FAILURE;
		}
	}

	/* Setup base signal handling. */
	signals_setup();

	/* Initialize cryptographic backend. */
	dnssec_crypto_init();

	/* Initialize pseudorandom number generator. */
	srand(time(NULL));

	/* Initialize logging subsystem. */
	log_init();
	if (verbose) {
		log_levels_add(LOG_TARGET_STDOUT, LOG_SOURCE_ANY, LOG_MASK(LOG_DEBUG));
	}

	/* Set up the configuration */
	int ret = set_config(confdb, config, max_conf_size);
	if (ret != KNOT_EOK) {
		log_close();
		dnssec_crypto_cleanup();
		return EXIT_FAILURE;
	}

	/* Reconfigure logging. */
	log_reconfigure(conf());

	/* Initialize server. */
	server_t server;
	ret = server_init(&server, conf()->cache.srv_bg_threads);
	if (ret != KNOT_EOK) {
		log_fatal("failed to initialize server (%s)", knot_strerror(ret));
		conf_free(conf());
		log_close();
		dnssec_crypto_cleanup();
		return EXIT_FAILURE;
	}

	/* Reconfigure server workers, interfaces, and databases.
	 * @note This MUST be done before we drop privileges. */
	ret = server_reconfigure(conf(), &server);
	if (ret != KNOT_EOK) {
		log_fatal("failed to configure server");
		server_wait(&server);
		server_deinit(&server);
		conf_free(conf());
		log_close();
		dnssec_crypto_cleanup();
		return EXIT_FAILURE;
	}

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
		dnssec_crypto_cleanup();
		return EXIT_FAILURE;
	}

	/* Connect to the system D-bus. */
	if (conf()->cache.srv_dbus_event != DBUS_EVENT_NONE &&
	    dbus_open() == KNOT_EOK) {
		int64_t delay = conf_get_int(conf(), C_SRV, C_DBUS_INIT_DELAY);
		sleep(delay);
	}

	/* Drop POSIX capabilities. */
	drop_capabilities();

	/* Activate global query modules. */
	ret = conf_activate_modules(conf(), &server, NULL, conf()->query_modules,
	                            &conf()->query_plan);
	if (ret != KNOT_EOK) {
		log_fatal("failed to activate query modules (%s)", knot_strerror(ret));
		server_wait(&server);
		server_deinit(&server);
		conf_free(conf());
		dbus_close();
		log_close();
		dnssec_crypto_cleanup();
		return EXIT_FAILURE;
	}

	/* Check and create PID file. */
	unsigned long pid = pid_check_and_create();
	if (pid == 0) {
		server_wait(&server);
		server_deinit(&server);
		conf_free(conf());
		dbus_close();
		log_close();
		dnssec_crypto_cleanup();
		return EXIT_FAILURE;
	}

	if (daemonize) {
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
	server_update_zones(conf(), &server, RELOAD_FULL);

	/* Check number of loaded zones. */
	if (knot_zonedb_size(server.zone_db) == 0) {
		log_warning("no zones loaded");
	}

	stats_reconfigure(conf(), &server);

	conf_val_t async_val = conf_get(conf(), C_SRV, C_ASYNC_START);
	bool async = conf_bool(&async_val);

	/* Start it up. */
	/* In async-start mode, start answering early, otherwise in the event loop. */
	if ((ret = server_start(&server, async)) != KNOT_EOK ||
	    (ret = event_loop(&server, socket, daemonize, pid, async)) != KNOT_EOK) {
		log_fatal("failed to start server (%s)", knot_strerror(ret));
		server_stop(&server);
		server_wait(&server);
		stats_deinit();
		pid_cleanup();
		server_deinit(&server);
		conf_free(conf());
		rcu_unregister_thread();
		dbus_close();
		log_close();
		dnssec_crypto_cleanup();
		return EXIT_FAILURE;
	}

	/* Teardown server. */
	server_stop(&server);
	server_wait(&server);
	stats_deinit();

	/* Cleanup PID file. */
	pid_cleanup();

	/* Free server and configuration. */
	server_deinit(&server);
	conf_free(conf());

	/* Unhook from RCU. */
	rcu_unregister_thread();

	dbus_close();

	log_info("shutting down");
	log_close();

	dnssec_crypto_cleanup();

	return EXIT_SUCCESS;
}
