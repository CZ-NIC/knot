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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <limits.h>

#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "libknot/common.h"
#include "libknot/dnssec/crypto.h"
#include "knot/knot.h"
#include "knot/server/server.h"
#include "knot/ctl/process.h"
#include "knot/ctl/remote.h"
#include "knot/conf/conf.h"
#include "knot/zone/timers.h"
#include "knot/server/tcp-handler.h"

/* Signal flags. */
static volatile short sig_req_stop = 0;
static volatile short sig_req_reload = 0;
static volatile short sig_stopping = 0;

/* \brief Signal started state to the init system. */
static void init_signal_started(void)
{
#ifdef ENABLE_SYSTEMD
	sd_notify(0, "READY=1");
#endif
}

/*! \brief atexit() handler for server code. */
static void knot_crypto_deinit(void)
{
	knot_crypto_cleanup();
	knot_crypto_cleanup_threads();
}

/*! \brief PID file cleanup handler. */
static void pid_cleanup(char *pidfile)
{
	if (pidfile && pid_remove(pidfile) < 0) {
		log_warning("failed to remove PID file");
	}
}

/*! \brief SIGINT signal handler. */
void interrupt_handle(int s)
{
	/* Reload configuration. */
	if (s == SIGHUP) {
		sig_req_reload = 1;
		return;
	}

	/* Stop server. */
	if (s == SIGINT || s == SIGTERM) {
		if (sig_stopping == 0) {
			sig_req_stop = 1;
			sig_stopping = 1;
		} else {
			exit(1);
		}
	}
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
static void event_loop(server_t *server)
{
	/* Setup signal handler. */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = interrupt_handle;
	sigaction(SIGINT,  &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP,  &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGALRM, &sa, NULL);
	pthread_sigmask(SIG_BLOCK, &sa.sa_mask, NULL);

	/* Bind to control interface. */
	uint8_t buf[KNOT_WIRE_MAX_PKTSIZE];
	size_t buflen = sizeof(buf);
	int remote = remote_bind(conf()->ctl.iface);

	/* Run event loop. */
	for (;;) {
		pthread_sigmask(SIG_UNBLOCK, &sa.sa_mask, NULL);
		int ret = remote_poll(remote);
		pthread_sigmask(SIG_BLOCK, &sa.sa_mask, NULL);

		/* Events. */
		if (ret > 0) {
			ret = remote_process(server, conf()->ctl.iface,
			                     remote, buf, buflen);
			switch (ret) {
			case KNOT_CTL_STOP:
				sig_req_stop = 1;
				break;
			default:
				break;
			}
		}

		/* Interrupts. */
		if (sig_req_stop) {
			sig_req_stop = 0;
			server_stop(server);
			break;
		}
		if (sig_req_reload) {
			sig_req_reload = 0;
			server_reload(server, conf()->filename);
		}
	}
	pthread_sigmask(SIG_UNBLOCK, &sa.sa_mask, NULL);

	/* Close remote control interface. */
	remote_unbind(conf()->ctl.iface, remote);

	/* Wait for server to finish. */
	server_wait(server);
}

static void help(void)
{
	printf("Usage: %sd [parameters]\n",
	       PACKAGE_NAME);
	printf("\nParameters:\n"
	       " -c, --config <file>     Select configuration file.\n"
	       " -d, --daemonize=[dir]   Run server as a daemon.\n"
	       " -V, --version           Print version of the server.\n"
	       " -h, --help              Print help and usage.\n");
}

int main(int argc, char **argv)
{
	/* Parse command line arguments. */
	int c = 0, li = 0;
	int daemonize = 0;
	const char *config_fn = conf_find_default();
	const char *daemon_root = "/";

	/* Long options. */
	struct option opts[] = {
		{"config",    required_argument, 0, 'c'},
		{"daemonize", optional_argument, 0, 'd'},
		{"version",   no_argument,       0, 'V'},
		{"help",      no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "c:dVh", opts, &li)) != -1) {
		switch (c)
		{
		case 'c':
			config_fn = optarg;
			break;
		case 'd':
			daemonize = 1;
			if (optarg) {
				daemon_root = optarg;
			}
			break;
		case 'V':
			printf("%s, version %s\n", "Knot DNS", PACKAGE_VERSION);
			return EXIT_SUCCESS;
		case 'h':
		case '?':
			help();
			return EXIT_SUCCESS;
		default:
			help();
			return EXIT_FAILURE;
		}
	}

	/* Check for non-option parameters. */
	if (argc - optind > 0) {
		help();
		return EXIT_FAILURE;
	}

	/* Now check if we want to daemonize. */
	if (daemonize) {
		if (daemon(1, 0) != 0) {
			fprintf(stderr, "Daemonization failed, shutting down...\n");
			return EXIT_FAILURE;
		}
	}

	/* Initialize cryptographic backend. */
	knot_crypto_init();
	knot_crypto_init_threads();
	atexit(knot_crypto_deinit);

	/* Initialize pseudorandom number generator. */
	srand(time(NULL));

	/* POSIX 1003.1e capabilities. */
	setup_capabilities();

	/* Default logging to std out/err. */
	log_init();

	/* Open configuration. */
	int res = conf_open(config_fn);
	conf_t *config = conf();
	if (res != KNOT_EOK) {
		log_fatal("failed to load configuration file '%s' (%s)",
		          config_fn, knot_strerror(res));
		return EXIT_FAILURE;
	}

	/* Initialize logging subsystem.
	 * @note We're logging since now. */
	log_reconfigure(config, NULL);
	conf_add_hook(config, CONF_LOG, log_reconfigure, NULL);

	/* Initialize server. */
	server_t server;
	res = server_init(&server, conf_bg_threads(config));
	if (res != KNOT_EOK) {
		log_fatal("failed to initialize server (%s)", knot_strerror(res));
		conf_free(conf());
		log_close();
		return EXIT_FAILURE;
	}

	/* Reconfigure server interfaces.
	 * @note This MUST be done before we drop privileges. */
	server_reconfigure(config, &server);
	conf_add_hook(config, CONF_ALL, server_reconfigure, &server);
	log_info("configured %zu interfaces and %zu zones",
	         list_size(&config->ifaces), hattrie_weight(config->zones));


	/* Alter privileges. */
	log_update_privileges(config->uid, config->gid);
	if (proc_update_privileges(config->uid, config->gid) != KNOT_EOK) {
		server_deinit(&server);
		conf_free(conf());
		log_close();
		return EXIT_FAILURE;
	}

	/* Check and create PID file. */
	long pid = (long)getpid();
	char *pidfile = NULL;
	if (daemonize) {
		pidfile = pid_check_and_create();
		if (pidfile == NULL) {
			server_deinit(&server);
			conf_free(conf());
			log_close();
			return EXIT_FAILURE;
		}

		log_info("PID stored in '%s'", pidfile);
		if (chdir(daemon_root) != 0) {
			log_warning("failed to change working directory to %s",
			            daemon_root);
		} else {
			log_info("changed directory to %s", daemon_root);
		}
	}

	/* Register base signal handling. */
	struct sigaction emptyset;
	memset(&emptyset, 0, sizeof(struct sigaction));
	emptyset.sa_handler = interrupt_handle;
	sigaction(SIGALRM, &emptyset, NULL);
	sigaction(SIGPIPE, &emptyset, NULL);

	/* Now we're going multithreaded. */
	rcu_register_thread();

	/* Populate zone database and add reconfiguration hook. */
	log_info("loading zones");
	server_update_zones(config, &server);
    //printf("prin to hook!!\n");
	conf_add_hook(config, CONF_ALL, server_update_zones, &server);

	/* Check number of loaded zones. */
	if (knot_zonedb_size(server.zone_db) == 0) {
		log_warning("no zones loaded");
	}

	/* Start it up. */
	log_info("starting server");
	res = server_start(&server, config->async_start);
	if (res != KNOT_EOK) {
		log_fatal("failed to start server (%s)", knot_strerror(res));
		server_deinit(&server);
		rcu_unregister_thread();
		pid_cleanup(pidfile);
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
	config = NULL; /* @note Invalidate pointer, as it may change now. */
	event_loop(&server);

	/* Teardown server and configuration. */
	server_deinit(&server);

	/* Free configuration. */
	conf_free(conf());

	/* Unhook from RCU. */
	rcu_unregister_thread();

	/* Cleanup PID file. */
	pid_cleanup(pidfile);

	log_info("shutting down");
	log_close();

	return EXIT_SUCCESS;
}
