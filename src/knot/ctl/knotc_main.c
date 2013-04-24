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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <ctype.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include "knot/common.h"
#include "common/descriptor.h"
#include "knot/ctl/process.h"
#include "knot/ctl/remote.h"
#include "knot/conf/conf.h"
#include "knot/zone/zone-load.h"
#include "knot/server/socket.h"
#include "knot/server/tcp-handler.h"
#include "libknot/util/wire.h"
#include "libknot/packet/query.h"
#include "libknot/packet/response.h"
#include "knot/zone/zone-load.h"

/*! \brief Controller constants. */
enum knotc_constants_t {
	WAITPID_TIMEOUT = 120   /*!< \brief Timeout for waiting for process. */
};

/*! \brief Controller flags. */
enum knotc_flag_t {
	F_NULL = 0 << 0,
	F_FORCE = 1 << 0,
	F_VERBOSE = 1 << 1,
	F_WAIT = 1 << 2,
	F_INTERACTIVE = 1 << 3,
	F_AUTO = 1 << 4,
	F_UNPRIVILEGED = 1 << 5,
	F_NOCONF = 1 << 6,
	F_DRYRUN = 1 << 7
};

/*! \brief Check if flag is present. */
static inline unsigned has_flag(unsigned flags, enum knotc_flag_t f)
{
	return flags & f;
}

/*! \brief Callback prototype for command. */
typedef int (*knot_cmdf_t)(int argc, char *argv[], unsigned flags);

/*! \brief Command table item. */
typedef struct knot_cmd_t {
	const char *name;
	knot_cmdf_t cb;
	const char *desc;
	int need_conf;
} knot_cmd_t;

/* Forward decls. */
static int cmd_start(int argc, char *argv[], unsigned flags);
static int cmd_stop(int argc, char *argv[], unsigned flags);
static int cmd_restart(int argc, char *argv[], unsigned flags);
static int cmd_reload(int argc, char *argv[], unsigned flags);
static int cmd_refresh(int argc, char *argv[], unsigned flags);
static int cmd_flush(int argc, char *argv[], unsigned flags);
static int cmd_status(int argc, char *argv[], unsigned flags);
static int cmd_zonestatus(int argc, char *argv[], unsigned flags);
static int cmd_checkconf(int argc, char *argv[], unsigned flags);
static int cmd_checkzone(int argc, char *argv[], unsigned flags);

/*! \brief Table of remote commands. */
knot_cmd_t knot_cmd_tbl[] = {
	{"start",     &cmd_start, "\tStart server (no-op if running).", 1},
	{"stop",      &cmd_stop, "\tStop server (no-op if running).", 1},
	{"restart",   &cmd_restart, "Restarts server (no-op if running).", 1},
	{"reload",    &cmd_reload, "\tReloads configuration and changed zones.",0},
	{"refresh",   &cmd_refresh,"Refresh slave zones (all if not specified).",0},
	{"flush",     &cmd_flush, "\tFlush journal and update zone files.",0},
	{"status",    &cmd_status, "\tCheck if server is running.",0},
	{"zonestatus",&cmd_zonestatus, "Show status of configured zones.",0},
	{"checkconf", &cmd_checkconf, "Check server configuration.",1},
	{"checkzone", &cmd_checkzone, "Check specified zone files.",1},
	{NULL, NULL, NULL,0}
};

/*! \brief Print help. */
void help(int argc, char **argv)
{
	printf("Usage: %sc [parameters] <action> [action_args]\n", PACKAGE_NAME);
	printf("\nParameters:\n"
	       " -c [file], --config=[file]\tSelect configuration file.\n"
	       " -s [server]               \tRemote server address (default %s)\n"
	       " -p [port]                 \tRemote server port (default %d)\n"
	       " -y [hmac:]name:key]       \tUse key_id specified on the command line.\n"
	       " -k [file]                 \tUse key file (as in config section 'keys').\n"
	       "                           \t  f.e. echo \"knotc-key hmac-md5 Wg==\" > knotc.key\n"
	       " -f, --force               \tForce operation - override some checks.\n"
	       " -v, --verbose             \tVerbose mode - additional runtime information.\n"
	       " -V, --version             \tPrint %s server version.\n"
	       " -w, --wait                \tWait for the server to finish start/stop operations.\n"
	       " -i, --interactive         \tInteractive mode (do not daemonize).\n"
	       " -h, --help                \tPrint help and usage.\n",
	       "127.0.0.1", REMOTE_DPORT, PACKAGE_NAME);
	printf("\nActions:\n");
	knot_cmd_t *c = knot_cmd_tbl;
	while (c->name != NULL) {
		printf(" %s\t\t\t%s\n", c->name, c->desc);
		++c;
	}
}

static int cmd_remote_print_reply(const knot_rrset_t *rr)
{
	/* Process first RRSet in data section. */
	if (knot_rrset_type(rr) != KNOT_RRTYPE_TXT) {
		return KNOT_EMALF;
	}
	
	for (uint16_t i = 0; i < knot_rrset_rdata_rr_count(rr); i++) {
		/* Parse TXT. */
		remote_print_txt(rr, i);
	}
	
	return KNOT_EOK;
}

static int cmd_remote_reply(int c)
{
	uint8_t *rwire = malloc(SOCKET_MTU_SZ);
	knot_packet_t *reply = knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	if (!rwire || !reply) {
		free(rwire);
		knot_packet_free(&reply);
		return KNOT_ENOMEM;
	}
	
	/* Read response packet. */
	int n = tcp_recv(c, rwire, SOCKET_MTU_SZ, NULL);
	if (n <= 0) {
		dbg_server("remote: couldn't receive response = %d\n", n);
		knot_packet_free(&reply);
		free(rwire);
		return KNOT_ECONN;
	}
	
	/* Parse packet and check response. */
	int ret = remote_parse(reply, rwire, n);
	if (ret == KNOT_EOK) {
		/* Check RCODE */
		ret = knot_packet_rcode(reply);
		switch(ret) {
		case KNOT_RCODE_NOERROR:
			if (knot_packet_authority_rrset_count(reply) > 0) {
				ret = cmd_remote_print_reply(reply->authority[0]);
			}
			break;
		case KNOT_RCODE_REFUSED:
			ret = KNOT_EDENIED;
			break;
		default:
			ret = KNOT_ERROR;
			break;
		}
	}
	
	/* Response cleanup. */
	knot_packet_free(&reply);
	free(rwire);
	return ret;
}

static int cmd_remote(const char *cmd, uint16_t rrt, int argc, char *argv[])
{
	int rc = 0;

	/* Check remote address. */
	conf_iface_t *r = conf()->ctl.iface;
	if (!r || !r->address) {
		log_server_error("No remote address for '%s' configured.\n",
		                 cmd);
		return 1;
	}
	
	/* Make query. */
	uint8_t *buf = NULL;
	size_t buflen = 0;
	knot_packet_t *qr = remote_query(cmd, r->key);
	if (!qr) {
		log_server_warning("Could not prepare query for '%s'.\n",
		                   cmd);
		return 1;
	}
	
	/* Build query data. */
	knot_rrset_t *rr = remote_build_rr("data.", rrt);
	for (int i = 0; i < argc; ++i) {
		switch(rrt) {
		case KNOT_RRTYPE_NS:
			remote_create_ns(rr, argv[i]);
			break;
		case KNOT_RRTYPE_TXT:
		default:
			remote_create_txt(rr, argv[i], strlen(argv[i]));
			break;
		}
	}
	remote_query_append(qr, rr);
	if (knot_packet_to_wire(qr, &buf, &buflen) != KNOT_EOK) {
		knot_rrset_deep_free(&rr, 1, 1);
		knot_packet_free(&qr);
		return 1;
	}

	if (r->key) {
		remote_query_sign(buf, &buflen, qr->max_size, r->key);
	}
	
	/* Send query. */
	int s = socket_create(r->family, SOCK_STREAM, IPPROTO_TCP);
	int conn_state = socket_connect(s, r->address, r->port);
	if (conn_state != KNOT_EOK || tcp_send(s, buf, buflen) <= 0) {
		log_server_error("Couldn't connect to remote host "
		                 " %s@%d.\n", r->address, r->port);
		rc = 1;
	}
	
	/* Wait for reply. */
	if (rc == 0) {
		int ret = KNOT_EOK;
		while (ret == KNOT_EOK) {
			ret = cmd_remote_reply(s);
			if (ret != KNOT_EOK && ret != KNOT_ECONN) {
				log_server_warning("Remote command reply: %s\n",
				                   knot_strerror(ret));
				rc = 1;
			}
		}
	}
	
	/* Cleanup. */
	if (rc == 0) printf("\n");
	knot_rrset_deep_free(&rr, 1, 1);
	
	/* Close connection. */
	socket_close(s);
	knot_packet_free(&qr);
	return rc;
}

static int tsig_parse_str(knot_tsig_key_t *key, const char *str)
{
	char *h = strdup(str);
	if (!h) {
		return KNOT_ENOMEM;
	}
	
	char *k = NULL, *s = NULL;
	if ((k = (char*)strchr(h, ':'))) { /* Second part - NAME|SECRET */
		*k++ = '\0';               /* String separator */
		s = (char*)strchr(k, ':'); /* Thirt part - |SECRET */
	}
	
	/* Determine algorithm. */

	int algorithm = KNOT_TSIG_ALG_HMAC_MD5;
	if (s) {
		*s++ = '\0';               /* Last part separator */
		knot_lookup_table_t *alg = NULL;
		alg = knot_lookup_by_name(knot_tsig_alg_domain_names, h);
		if (alg) {
			algorithm = alg->id;
		} else {
			free(h);
			return KNOT_EINVAL;
		}
	} else {
		s = k; /* Ignore first part, push down. */
		k = h;
	}
	
	/* Parse key name. */

	int result = knot_tsig_create_key(k, algorithm, s, key);
	free(h);
	return result;
}

static int tsig_parse_line(knot_tsig_key_t *k, char *l)
{
	const char *n, *a, *s;
	n = a = s = NULL;
	int fw = 1; /* 0 = reading word, 1 = between words */
	while (*l != '\0') {
		if (isspace((unsigned char)(*l)) || *l == '"') {
			*l = '\0';
			fw = 1; /* End word. */
		} else if (fw) {
			if      (!n) { n = l; }
			else if (!a) { a = l; }
			else         { s = l; }
			fw = 0; /* Start word. */
		}
		l++;
	}

	/* No name parsed - assume wrong format. */
	if (!n) {
		return KNOT_EMALF;
	}
	
	/* Assume hmac-md5 if no algo specified. */
	if (!s) {
		s = a;
		a = "hmac-md5";
	}
	
	/* Lookup algorithm. */
	knot_lookup_table_t *alg;
	alg = knot_lookup_by_name(knot_tsig_alg_domain_names, a);

	if (!alg) {
		return KNOT_EMALF;
	}
	
	/* Create the key data. */
	return knot_tsig_create_key(n, alg->id, s, k);
}

static int tsig_parse_file(knot_tsig_key_t *k, const char *f)
{
	FILE* fp = fopen(f, "r");
	if (!fp) {
		log_server_error("Couldn't open key-file '%s'.\n", f);
		return KNOT_EINVAL;
	}
	
	int c = 0;
	int ret = KNOT_EOK;
	char *line = malloc(64);
	size_t llen = 0;
	size_t lres = 0;
	if (line) {
		lres = 64;
	}
	
	while ((c = fgetc(fp)) != EOF) {
		if (mreserve(&line, sizeof(char), llen + 1, 512, &lres) != 0) {
			ret = KNOT_ENOMEM;
			break;
		}
		if (c == '\n') {
			if (k->name) {
				log_server_error("Only 1 key definition "
				                 "allowed in '%s'.\n",
				                 f);
				ret = KNOT_EMALF;
				break;
			}
			line[llen++] = '\0';
			ret = tsig_parse_line(k, line);
			llen = 0;
		} else {
			line[llen++] = (char)c;
		}
		
	}
	
	free(line);
	fclose(fp);
	return ret;
}

int main(int argc, char **argv)
{
	/* Parse command line arguments */
	int c = 0, li = 0;
	unsigned flags = F_NULL;
	char *config_fn = NULL;
	char *default_config = conf_find_default();
	
	/* Remote server descriptor. */
	int ret = KNOT_EOK;
	const char *r_addr = NULL;
	int r_port = -1;
	knot_tsig_key_t r_key;
	memset(&r_key, 0, sizeof(knot_tsig_key_t));
	
	/* Initialize. */
	log_init();
	log_levels_set(LOG_SYSLOG, LOG_ANY, 0);
	
	/* Long options. */
	struct option opts[] = {
		{"wait", no_argument, 0, 'w'},
		{"force", no_argument, 0, 'f'},
		{"config", required_argument, 0, 'c'},
		{"verbose", no_argument, 0, 'v'},
		{"interactive", no_argument, 0, 'i'},
		{"version", no_argument, 0, 'V'},
		{"help", no_argument, 0, 'h'},
		{"server", required_argument, 0, 's' },
		{"port", required_argument, 0, 's' },
		{"y", required_argument, 0, 'y' },
		{"k", required_argument, 0, 'k' },
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "s:p:y:k:wfc:viVh", opts, &li)) != -1) {
		switch (c) {
		case 's':
			r_addr = optarg;
			break;
		case 'p':
			r_port = atoi(optarg);
			break;
		case 'y':
			ret = tsig_parse_str(&r_key, optarg);
			if (ret != KNOT_EOK) {
				log_server_error("Couldn't parse TSIG key '%s' "
				                 "\n", optarg);
				knot_tsig_key_free(&r_key);
				log_close();
				return 1;
			}
			break;
		case 'k':
			ret = tsig_parse_file(&r_key, optarg);
			if (ret != KNOT_EOK) {
				log_server_error("Couldn't parse TSIG key file "
				                 "'%s'\n", optarg);
				knot_tsig_key_free(&r_key);
				log_close();
				return 1;
			}
			break;
		case 'w':
			flags |= F_WAIT;
			break;
		case 'f':
			flags |= F_FORCE;
			break;
		case 'v':
			flags |= F_VERBOSE;
			break;
		case 'i':
			flags |= F_INTERACTIVE;
			break;
		case 'c':
			config_fn = strdup(optarg);
			break;
		case 'V':
			printf("%s, version %s\n", "Knot DNS", PACKAGE_VERSION);
			log_close();
			free(config_fn);
			free(default_config);
			return 0;
		case 'h':
		case '?':
		default:
			help(argc, argv);
			log_close();
			free(config_fn);
			free(default_config);
			return 1;
		}
	}

	/* Check if there's at least one remaining non-option. */
	if (argc - optind < 1) {
		help(argc, argv);
		knot_tsig_key_free(&r_key);
		log_close();
		free(config_fn);
		free(default_config);
		return 1;
	}
	
	/* Find requested command. */
	knot_cmd_t *cmd = knot_cmd_tbl;
	while (cmd->name) {
		if (strcmp(cmd->name, argv[optind]) == 0) {
			break;
		}
		++cmd;
	}
	
	/* Command not found. */
	if (!cmd->name) {
		log_server_error("Invalid command: '%s'\n", argv[optind]);
		knot_tsig_key_free(&r_key);
		log_close();
		free(config_fn);
		free(default_config);
		return 1;
	}

	/* Open config, allow if not exists. */
	if (conf_open(config_fn) != KNOT_EOK) {
		if(conf_open(default_config) != KNOT_EOK) {
			flags |= F_NOCONF;
		}
	}
	
	/* Create remote iface if not present in config. */
	conf_iface_t *ctl_if = conf()->ctl.iface;
	if (!ctl_if) {
		ctl_if = malloc(sizeof(conf_iface_t));
		assert(ctl_if);
		conf()->ctl.iface = ctl_if;
		memset(ctl_if, 0, sizeof(conf_iface_t));
		
		/* Fill defaults. */
		if (!r_addr) r_addr = "127.0.0.1";
		if (r_port < 0) r_port =  REMOTE_DPORT;

		/* Create empty key. */
		if (r_key.name) {
			ctl_if->key = malloc(sizeof(knot_tsig_key_t));
			if (ctl_if->key) {
				memcpy(ctl_if->key, &r_key, sizeof(knot_tsig_key_t));
			}
		}
	} else {
		if (r_key.name) {
			knot_tsig_key_free(ctl_if->key);
			ctl_if->key = &r_key;
		}
	}
	
	/* Override from command line. */
	if (r_addr) {
		free(ctl_if->address);
		ctl_if->address = strdup(r_addr);
		ctl_if->family = AF_INET;
		if (strchr(r_addr, ':')) { /* Dumb way to check for v6 addr. */
			ctl_if->family = AF_INET6;
		}
	}
	if (r_port > -1) ctl_if->port = r_port;

	/* Verbose mode. */
	if (has_flag(flags, F_VERBOSE)) {
		log_levels_add(LOGT_STDOUT, LOG_ANY,
		               LOG_MASK(LOG_INFO) | LOG_MASK(LOG_DEBUG));
	}

	/* Execute command. */
	int rc = cmd->cb(argc - optind - 1, argv + optind + 1, flags);

	/* Finish */
	knot_tsig_key_free(&r_key); /* Not cleaned by config deinit. */
	log_close();
	free(config_fn);
	free(default_config);
	return rc;
}

static int cmd_start(int argc, char *argv[], unsigned flags)
{
	/* Check config. */
	if (has_flag(flags, F_NOCONF)) {
		log_server_error("Couldn't parse config file, refusing to "
		                 "continue.\n");
		return 1;
	}
	
	/* Fetch PID. */
	char *pidfile = pid_filename();
	pid_t pid = pid_read(pidfile);
	log_server_info("Starting server...\n");
	
	/* Prevent concurrent daemon launch. */
	int rc = 0;
	struct stat st;
	int is_pidf = 0;
	
	/* Check PID. */
	if (pid > 0 && pid_running(pid)) {
		log_server_error("Server PID found, already running.\n");
		is_pidf = 1;
	} else if (stat(pidfile, &st) == 0) {
		log_server_warning("PID file '%s' exists, another process "
		                   "is starting or PID file is stale.\n",
		                   pidfile);
		is_pidf = 1;
	}
	if (is_pidf) {
		if (!has_flag(flags, F_FORCE)) {
			free(pidfile);
			return 1;
		} else {
			log_server_info("Forcing server start.\n");
			pid_remove(pidfile);
		}
	}
	
	/* Prepare command */
	const char *cfg = conf()->filename;
	size_t args_c = 6;
	const char *args[] = {
		PROJECT_EXEC,
		has_flag(flags, F_INTERACTIVE) ? "" : "-d",
		cfg ? "-c" : "",
		cfg ? cfg : "",
		has_flag(flags, F_VERBOSE) ? "-v" : "",
		argc > 0 ? argv[0] : ""
	};
	
	/* Execute command */
	if (has_flag(flags, F_INTERACTIVE)) {
		log_server_info("Running in interactive mode.\n");
		fflush(stderr);
		fflush(stdout);
	}
	if ((rc = cmd_exec(args, args_c)) < 0) {
		pid_remove(pidfile);
		rc = 1;
	}
	fflush(stderr);
	fflush(stdout);

	/* Wait for finish */
	if (has_flag(flags, F_WAIT) && !has_flag(flags, F_INTERACTIVE)) {
		if (has_flag(flags, F_VERBOSE)) {
			log_server_info("Waiting for server to load.\n");
		}

		/* Periodically read pidfile and wait for valid result. */
		pid = 0;
		while (pid == 0 || !pid_running(pid)) {
			pid = pid_read(pidfile);
			struct timeval tv;
			tv.tv_sec = 0;
			tv.tv_usec = 500 * 1000;
			select(0, 0, 0, 0, &tv);
		}
	}
	
	free(pidfile);
	return rc;
}

static int cmd_stop(int argc, char *argv[], unsigned flags)
{
	/* Check config. */
	if (has_flag(flags, F_NOCONF)) {
		log_server_error("Couldn't parse config file, refusing to "
		                 "continue.\n");
		return 1;
	}

	/* Fetch PID. */
	char *pidfile = pid_filename();
	pid_t pid = pid_read(pidfile);
	int rc = 0;
	struct stat st;
	
	/* Check for non-existent PID file. */
	int has_pidf = (stat(pidfile, &st) == 0);
	if(has_pidf && pid <= 0) {
		log_server_warning("Empty PID file '%s' exists, daemon process "
		                   "is starting or PID file is stale.\n",
		                   pidfile);
		free(pidfile);
		return 1;
	} else if (pid <= 0 || !pid_running(pid)) {
		log_server_warning("Server PID not found, "
		                   "probably not running.\n");
		if (!has_flag(flags, F_FORCE)) {
			free(pidfile);
			return 1;
		} else {
			log_server_info("Forcing server stop.\n");
		}
	}

	/* Stop */
	log_server_info("Stopping server...\n");
	if (kill(pid, SIGTERM) < 0) {
		pid_remove(pidfile);
		rc = 1;
	}
	

	/* Wait for finish */
	if (rc == 0 && has_flag(flags, F_WAIT)) {
		log_server_info("Waiting for server to finish.\n");
		while (pid_running(pid)) {
			struct timeval tv;
			tv.tv_sec = 0;
			tv.tv_usec = 500 * 1000;
			select(0, 0, 0, 0, &tv);
			pid = pid_read(pidfile); /* Update */
		}
	}
	
	return rc;
}

static int cmd_restart(int argc, char *argv[], unsigned flags)
{
	/* Check config. */
	if (has_flag(flags, F_NOCONF)) {
		log_server_error("Couldn't parse config file, refusing to "
		                 "continue.\n");
		return 1;
	}
	
	int rc = 0;
	rc |= cmd_stop(argc, argv, flags | F_WAIT);
	rc |= cmd_start(argc, argv, flags);
	return rc;
}

static int cmd_reload(int argc, char *argv[], unsigned flags)
{
	return cmd_remote("reload", KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_refresh(int argc, char *argv[], unsigned flags)
{
	return cmd_remote("refresh", KNOT_RRTYPE_NS, argc, argv);
}

static int cmd_flush(int argc, char *argv[], unsigned flags)
{
	return cmd_remote("flush", KNOT_RRTYPE_NS, argc, argv);
}

static int cmd_status(int argc, char *argv[], unsigned flags)
{
	return cmd_remote("status", KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_zonestatus(int argc, char *argv[], unsigned flags)
{
	return cmd_remote("zonestatus", KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_checkconf(int argc, char *argv[], unsigned flags)
{
	/* Check config. */
	if (has_flag(flags, F_NOCONF)) {
		log_server_error("Couldn't parse config file, refusing to "
		                 "continue.\n");
		return 1;
	} else {
		log_server_info("OK, configuration is valid.\n");
	}
	
	return 0;
}

static int cmd_checkzone(int argc, char *argv[], unsigned flags)
{
	/* Zone checking */
	int rc = 0;
	node *n = 0;
	
	/* Generate databases for all zones */
	WALK_LIST(n, conf()->zones) {
		/* Fetch zone */
		conf_zone_t *zone = (conf_zone_t *) n;
		int zone_match = 0;
		for (unsigned i = 0; i < argc; ++i) {
			size_t len = strlen(zone->name);
			
			/* All (except root) without final dot */
			if (len > 1) {
				len -= 1;
			}
			if (strncmp(zone->name, argv[i], len) == 0) {
				zone_match = 1;
				break;
			}
		}

		if (!zone_match && argc > 0) {
			/* WALK_LIST is a for-cycle. */
			continue;
		}
		
		/* Create zone loader context. */
		zloader_t *l = NULL;
		int ret = knot_zload_open(&l, zone->file, zone->name,
		                          zone->enable_checks);
		if (ret != KNOT_EOK) {
			log_zone_error("Could not open zone %s (%s).\n",
			               zone->name, knot_strerror(ret));
			knot_zload_close(l);
			rc = 1;
			continue;
		}
		
		knot_zone_t *z = knot_zload_load(l);
		if (z == NULL) {
			log_zone_error("Loading of zone %s failed.\n",
			               zone->name);
			knot_zload_close(l);
			rc = 1;
			continue;
		}
		
		knot_zone_deep_free(&z);
		knot_zload_close(l);
		
		log_zone_info("Zone %s OK.\n", zone->name);
	}

	return rc;
}
