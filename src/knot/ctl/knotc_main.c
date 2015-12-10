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
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <ctype.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include "dnssec/crypto.h"
#include "libknot/libknot.h"
#include "knot/common/log.h"
#include "knot/ctl/estimator.h"
#include "knot/ctl/remote.h"
#include "knot/conf/conf.h"
#include "knot/server/tcp-handler.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/zone-load.h"
#include "contrib/macros.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/string.h"

/*! \brief Controller flags. */
enum knotc_flag_t {
	F_NULL     = 0,
	F_FORCE    = 1 << 0,
	F_VERBOSE  = 1 << 1,
	F_NOCONFDB = 1 << 2
};

/*! \brief Check if flag is present. */
static bool has_flag(unsigned flags, enum knotc_flag_t f)
{
	return (flags & f) != 0;
}

/*! \brief Callback arguments. */
typedef struct cmd_args {
	struct sockaddr_storage *addr;
	knot_tsig_key_t *key;
	int argc;
	char **argv;
	unsigned flags;
	const char *conf_db;
} cmd_args_t;

/*! \brief Callback prototype for command. */
typedef int (*knot_cmdf_t)(cmd_args_t *args);

/*! \brief Command table item. */
typedef struct knot_cmd {
	knot_cmdf_t cb;
	const char *name;
	const char *params;
	const char *desc;
} knot_cmd_t;

/* Forward decls. */
static int cmd_stop(cmd_args_t *args);
static int cmd_reload(cmd_args_t *args);
static int cmd_refresh(cmd_args_t *args);
static int cmd_flush(cmd_args_t *args);
static int cmd_status(cmd_args_t *args);
static int cmd_zonestatus(cmd_args_t *args);
static int cmd_checkconf(cmd_args_t *args);
static int cmd_checkzone(cmd_args_t *args);
static int cmd_memstats(cmd_args_t *args);
static int cmd_signzone(cmd_args_t *args);
static int cmd_conf_import(cmd_args_t *args);
static int cmd_conf_export(cmd_args_t *args);
static int cmd_conf_desc(cmd_args_t *args);
static int cmd_conf_read(cmd_args_t *args);
static int cmd_conf_begin(cmd_args_t *args);
static int cmd_conf_commit(cmd_args_t *args);
static int cmd_conf_abort(cmd_args_t *args);
static int cmd_conf_diff(cmd_args_t *args);
static int cmd_conf_get(cmd_args_t *args);
static int cmd_conf_set(cmd_args_t *args);
static int cmd_conf_unset(cmd_args_t *args);

/*! \brief Table of remote commands. */
knot_cmd_t knot_cmd_tbl[] = {
	{ &cmd_stop,        "stop",        "",                     "Stop server." },
	{ &cmd_reload,      "reload",      "[<zone>...]",          "Reload particular zones or reload whole\n"
	                         "                                   configuration and changed zones." },
	{ &cmd_refresh,     "refresh",     "[<zone>...]",          "Refresh slave zones. Flag '-f' forces retransfer\n"
	                         "                                   (zone(s) must be specified)." },
	{ &cmd_flush,       "flush",       "[<zone>...]",          "Flush journal and update zone files." },
	{ &cmd_status,      "status",      "",                     "Check if server is running." },
	{ &cmd_zonestatus,  "zonestatus",  "[<zone>...]",          "Show status of configured zones." },
	{ &cmd_checkconf,   "checkconf",   "",                     "Check current server configuration." },
	{ &cmd_checkzone,   "checkzone",   "[<zone>...]",          "Check zones." },
	{ &cmd_memstats,    "memstats",    "[<zone>...]",          "Estimate memory use for zones." },
	{ &cmd_signzone,    "signzone",    "<zone>...",            "Sign zones with available DNSSEC keys." },
	{ &cmd_conf_import, "conf-import", "<filename>",           "Offline config DB import from file." },
	{ &cmd_conf_export, "conf-export", "<filename>",           "Export config DB to file." },
	{ &cmd_conf_desc,   "conf-desc",   "[<item>]",             "Get config DB item list." },
	{ &cmd_conf_read,   "conf-read",   "[<item>]",             "Read item(s) from active config DB." },
	{ &cmd_conf_begin,  "conf-begin",  "",                     "Begin config DB transaction." },
	{ &cmd_conf_commit, "conf-commit", "",                     "Commit config DB transaction." },
	{ &cmd_conf_abort,  "conf-abort",  "",                     "Rollback config DB transaction." },
	{ &cmd_conf_diff,   "conf-diff",   "[<item>]",             "Get config DB transaction difference." },
	{ &cmd_conf_get,    "conf-get",    "[<item>]",             "Get item(s) from config DB transaction." },
	{ &cmd_conf_set,    "conf-set",    "<item> [<data>...]",   "Set item(s) in config DB transaction." },
	{ &cmd_conf_unset,  "conf-unset",  "[<item>] [<data>...]", "Unset item(s) in config DB transaction." },
	{ NULL }
};

/*! \brief Print help. */
void help(void)
{
	printf("Usage: %sc [parameters] <action> [action_args]\n", PACKAGE_NAME);
	printf("\nParameters:\n"
	       " -c, --config <file>              Select configuration file.\n"
	       "                                   (default %s)\n"
	       " -C, --confdb <dir>               Select configuration database directory.\n"
	       " -s, --server <server>            Remote UNIX socket/IP address.\n"
	       "                                   (default %s)\n"
	       " -p, --port <port>                Remote server port (only for IP).\n"
	       " -y, --key <[hmac:]name:key>      Use key specified on the command line.\n"
	       "                                   (default algorithm is hmac-md5)\n"
	       " -k, --keyfile <file>             Read key from file (same format as -y).\n"
	       " -f, --force                      Force operation - override some checks.\n"
	       " -v, --verbose                    Verbose mode - additional runtime information.\n"
	       " -V, --version                    Print %s server version.\n"
	       " -h, --help                       Print help and usage.\n",
	       CONF_DEFAULT_FILE, RUN_DIR "/knot.sock", PACKAGE_NAME);
	printf("\nActions:\n");
	knot_cmd_t *c = knot_cmd_tbl;
	while (c->name != NULL) {
		printf(" %-11s %-20s %s\n", c->name, c->params, c->desc);
		++c;
	}
	printf("\nThe item argument must be in the section[identifier].item format.\n");
	printf("\nIf optional <zone> parameter is not specified, command is applied to all zones.\n\n");
}

static int cmd_remote_print_reply(const knot_rrset_t *rr)
{
	if (rr->type != KNOT_RRTYPE_TXT) {
		return KNOT_EMALF;
	}

	uint16_t rr_count = rr->rrs.rr_count;
	for (uint16_t i = 0; i < rr_count; i++) {
		/* Parse TXT. */
		remote_print_txt(rr, i);
	}

	return KNOT_EOK;
}

static int cmd_remote_reply(int c, struct timeval *timeout)
{
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (!pkt) {
		return KNOT_ENOMEM;
	}

	/* Read response packet. */
	int n = net_dns_tcp_recv(c, pkt->wire, pkt->max_size, timeout);
	if (n <= 0) {
		knot_pkt_free(&pkt);
		return KNOT_ECONN;
	} else {
		pkt->size = n;
	}

	/* Parse packet and check response. */
	int ret = remote_parse(pkt);
	if (ret != KNOT_EOK) {
		knot_pkt_free(&pkt);
		return ret;
	}

	/* Check RCODE */
	const knot_pktsection_t *authority = knot_pkt_section(pkt, KNOT_AUTHORITY);
	ret = knot_wire_get_rcode(pkt->wire);
	switch(ret) {
	case KNOT_RCODE_NOERROR:
		if (authority->count > 0) {
			ret = cmd_remote_print_reply(knot_pkt_rr(authority, 0));
		}
		break;
	case KNOT_RCODE_REFUSED:
		ret = KNOT_EDENIED;
		break;
	default:
		ret = KNOT_ERROR;
		break;
	}

	knot_pkt_free(&pkt);
	return ret;
}

static int cmd_remote(struct sockaddr_storage *addr, knot_tsig_key_t *key,
                      const char *cmd, uint16_t rrt, int argc, char *argv[])
{
	int rc = 0;

	/* Make query. */
	knot_pkt_t *pkt = remote_query(cmd, key);
	if (!pkt) {
		log_warning("failed to prepare query for '%s'", cmd);
		return 1;
	}

	/* Build query data. */
	knot_pkt_begin(pkt, KNOT_AUTHORITY);
	if (argc > 0) {
		knot_rrset_t rr;
		int res = remote_build_rr(&rr, "data.", rrt);
		if (res != KNOT_EOK) {
			log_error("failed to create the query");
			knot_pkt_free(&pkt);
			return 1;
		}
		for (uint16_t i = 0; i < argc; ++i) {
			switch(rrt) {
			case KNOT_RRTYPE_NS:
				remote_create_ns(&rr, argv[i]);
				break;
			case KNOT_RRTYPE_TXT:
			default:
				remote_create_txt(&rr, argv[i], strlen(argv[i]), i);
				break;
			}
		}
		res = knot_pkt_put(pkt, 0, &rr, KNOT_PF_FREE);
		if (res != KNOT_EOK) {
			log_error("failed to create the query");
			knot_rrset_clear(&rr, NULL);
			knot_pkt_free(&pkt);
			return 1;
		}
	}

	if (key) {
		int res = remote_query_sign(pkt->wire, &pkt->size, pkt->max_size,
		                            key);
		if (res != KNOT_EOK) {
			log_error("failed to sign the packet");
			knot_pkt_free(&pkt);
			return 1;
		}
	}

	/* Default timeout. */
	conf_val_t val = conf_get(conf(), C_SRV, C_TCP_REPLY_TIMEOUT);
	const struct timeval tv_reply = { conf_int(&val), 0 };

	/* Connect to remote. */
	char addr_str[SOCKADDR_STRLEN] = { 0 };
	sockaddr_tostr(addr_str, sizeof(addr_str), addr);

	int s = net_connected_socket(SOCK_STREAM, addr, NULL);
	if (s < 0) {
		log_error("failed to connect to remote host '%s'", addr_str);
		knot_pkt_free(&pkt);
		return 1;
	}

	/* Send and free packet. */
	struct timeval tv = tv_reply;
	int ret = net_dns_tcp_send(s, pkt->wire, pkt->size, &tv);
	knot_pkt_free(&pkt);

	/* Evaluate and wait for reply. */
	if (ret <= 0) {
		log_error("failed to connect to remote host '%s'", addr_str);
		close(s);
		return 1;
	}

	/* Wait for reply. */
	ret = KNOT_EOK;
	while (ret == KNOT_EOK) {
		tv = tv_reply;
		ret = cmd_remote_reply(s, &tv);
		if (ret != KNOT_EOK) {
			if (ret != KNOT_ECONN) {
				log_notice("remote command reply: %s",
				           knot_strerror(ret));
				rc = 1;
			}
			break;
		}
	}

	/* Cleanup. */
	if (rc == 0) {
		printf("\n");
	}

	/* Close connection. */
	close(s);
	return rc;
}

int main(int argc, char **argv)
{
	/* Parse command line arguments */
	int c = 0, li = 0, rc = 0;
	unsigned flags = F_NULL;
	const char *config_fn = CONF_DEFAULT_FILE;
	const char *config_db = NULL;

	/* Remote server descriptor. */
	const char *r_addr = NULL;
	int r_port = -1;
	knot_tsig_key_t r_key;
	memset(&r_key, 0, sizeof(knot_tsig_key_t));

	/* Initialize. */
	log_init();
	log_levels_set(LOG_SYSLOG, LOG_ANY, 0);

	/* Long options. */
	struct option opts[] = {
		{"config",  required_argument, 0, 'c' },
		{"confdb",  required_argument, 0, 'C' },
		{"server",  required_argument, 0, 's' },
		{"port",    required_argument, 0, 'p' },
		{"key",     required_argument, 0, 'y' },
		{"keyfile", required_argument, 0, 'k' },
		{"force",   no_argument,       0, 'f' },
		{"verbose", no_argument,       0, 'v' },
		{"help",    no_argument,       0, 'h' },
		{"version", no_argument,       0, 'V' },
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "s:p:y:k:fc:C:vVh", opts, &li)) != -1) {
		switch (c) {
		case 'c':
			config_fn = optarg;
			break;
		case 'C':
			config_db = optarg;
			break;
		case 's':
			r_addr = optarg;
			break;
		case 'p':
			r_port = atoi(optarg);
			break;
		case 'y':
			knot_tsig_key_deinit(&r_key);
			if (knot_tsig_key_init_str(&r_key, optarg) != KNOT_EOK) {
				rc = 1;
				log_error("failed to parse TSIG key '%s'", optarg);
				goto exit;
			}
			break;
		case 'k':
			knot_tsig_key_deinit(&r_key);
			if (knot_tsig_key_init_file(&r_key, optarg) != KNOT_EOK) {
				rc = 1;
				log_error("failed to parse TSIG key file '%s'", optarg);
				goto exit;
			}
			break;
		case 'f':
			flags |= F_FORCE;
			break;
		case 'v':
			flags |= F_VERBOSE;
			break;
		case 'V':
			rc = 0;
			printf("%s, version %s\n", "Knot DNS", PACKAGE_VERSION);
			goto exit;
		case 'h':
		case '?':
			rc = 0;
			help();
			goto exit;
		default:
			rc = 1;
			help();
			goto exit;
		}
	}

	/* Check if there's at least one remaining non-option. */
	if (argc - optind < 1) {
		rc = 1;
		help();
		goto exit;
	}

	/* Check for existing config DB destination. */
	struct stat st;
	if (config_db != NULL && stat(config_db, &st) != 0) {
		flags |= F_NOCONFDB;
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
		log_fatal("invalid command: '%s'", argv[optind]);
		rc = 1;
		goto exit;
	}

	/* Open configuration. */
	conf_t *new_conf = NULL;
	if (config_db == NULL) {
		int ret = conf_new(&new_conf, conf_scheme, NULL);
		if (ret != KNOT_EOK) {
			log_fatal("failed to initialize configuration database "
			          "(%s)", knot_strerror(ret));
			rc = 1;
			goto exit;
		}

		/* Import the configuration file. */
		ret = conf_import(new_conf, config_fn, true);
		if (ret != KNOT_EOK) {
			log_fatal("failed to load configuration file (%s)",
			          knot_strerror(ret));
			conf_free(new_conf, false);
			rc = 1;
			goto exit;
		}

		new_conf->filename = strdup(config_fn);
	} else {
		/* Open configuration database. */
		int ret = conf_new(&new_conf, conf_scheme, config_db);
		if (ret != KNOT_EOK) {
			log_fatal("failed to open configuration database '%s' "
			          "(%s)", config_db, knot_strerror(ret));
			rc = 1;
			goto exit;
		}
	}

	/* Run post-open config operations. */
	int ret = conf_post_open(new_conf);
	if (ret != KNOT_EOK) {
		log_fatal("failed to use configuration (%s)", knot_strerror(ret));
		conf_free(new_conf, false);
		rc = 1;
		goto exit;
	}

	/* Update to the new config. */
	conf_update(new_conf);

	/* Get control address. */
	conf_val_t listen_val = conf_get(conf(), C_CTL, C_LISTEN);
	conf_val_t rundir_val = conf_get(conf(), C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&rundir_val, NULL);
	struct sockaddr_storage addr = conf_addr(&listen_val, rundir);
	free(rundir);

	/* Override from command line. */
	if (r_addr) {
		/* Check for v6 address. */
		int family = AF_INET;
		if (strchr(r_addr, ':')) {
			family = AF_INET6;
		}

		/* Is a valid UNIX socket or at least contains slash ? */
		struct stat st;
		bool has_slash = strchr(r_addr, '/') != NULL;
		bool is_file = stat(r_addr, &st) == 0;
		if (has_slash || (is_file && S_ISSOCK(st.st_mode))) {
			family = AF_UNIX;
		}

		sockaddr_set(&addr, family, r_addr, sockaddr_port(&addr));
	}

	if (r_port > 0) {
		sockaddr_port_set(&addr, r_port);
	}

	/* Verbose mode. */
	if (has_flag(flags, F_VERBOSE)) {
		log_levels_add(LOGT_STDOUT, LOG_ANY,
		               LOG_MASK(LOG_INFO) | LOG_MASK(LOG_DEBUG));
	}

	cmd_args_t args = {
		&addr,
		r_key.name != NULL ? &r_key : NULL,
		argc - optind - 1,
		argv + optind + 1,
		flags,
		config_db
	};

	/* Execute command. */
	dnssec_crypto_init();
	rc = cmd->cb(&args);
	dnssec_crypto_cleanup();

exit:
	/* Finish */
	knot_tsig_key_deinit(&r_key);
	conf_free(conf(), false);
	log_close();

	return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int cmd_stop(cmd_args_t *args)
{
	if (args->argc > 0) {
		printf("command does not take arguments\n");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->addr, args->key, "stop", KNOT_RRTYPE_TXT,
	                  0, NULL);
}

static int cmd_reload(cmd_args_t *args)
{
	return cmd_remote(args->addr, args->key, "reload", KNOT_RRTYPE_NS,
	                  args->argc, args->argv);
}

static int cmd_refresh(cmd_args_t *args)
{
	const char *action = has_flag(args->flags, F_FORCE) ?
	                     "retransfer" : "refresh";

	return cmd_remote(args->addr, args->key, action, KNOT_RRTYPE_NS,
	                  args->argc, args->argv);
}

static int cmd_flush(cmd_args_t *args)
{
	return cmd_remote(args->addr, args->key, "flush", KNOT_RRTYPE_NS,
	                  args->argc, args->argv);
}

static int cmd_status(cmd_args_t *args)
{
	if (args->argc > 0) {
		printf("command does not take arguments\n");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->addr, args->key, "status", KNOT_RRTYPE_TXT,
	                  0, NULL);
}

static int cmd_zonestatus(cmd_args_t *args)
{
	return cmd_remote(args->addr, args->key, "zonestatus", KNOT_RRTYPE_NS,
	                  args->argc, args->argv);
}

static int cmd_signzone(cmd_args_t *args)
{
	return cmd_remote(args->addr, args->key, "signzone", KNOT_RRTYPE_NS,
	                  args->argc, args->argv);
}

static int cmd_conf_import(cmd_args_t *args)
{
	if (args->argc != 1) {
		printf("command takes one argument\n");
		return KNOT_EINVAL;
	}

	if (args->conf_db == NULL) {
		printf("no destination config DB specified\n");
		return KNOT_EINVAL;
	}

	if (!has_flag(args->flags, F_NOCONFDB) && !has_flag(args->flags, F_FORCE)) {
		printf("use force option to overwrite the existing destination "
		       "and ensure the server is not running!\n");
		return KNOT_EDENIED;
	}

	conf_t *new_conf = NULL;
	int ret = conf_new(&new_conf, conf_scheme, args->conf_db);
	if (ret == KNOT_EOK) {
		ret = conf_import(new_conf, args->argv[0], true);
	}

	conf_free(new_conf, false);

	printf("%s\n", knot_strerror(ret));

	return ret;
}

static int cmd_conf_export(cmd_args_t *args)
{
	if (args->argc != 1) {
		printf("command takes one argument\n");
		return KNOT_EINVAL;
	}

	int ret = conf_export(conf(), args->argv[0], YP_SNONE);

	printf("%s\n", knot_strerror(ret));

	return ret;
}

static int cmd_conf_desc(cmd_args_t *args)
{
	if (args->argc > 1) {
		printf("command takes no or one argument\n");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->addr, args->key, "conf-desc", KNOT_RRTYPE_TXT,
	                  args->argc, args->argv);
}

static int cmd_conf_read(cmd_args_t *args)
{
	if (args->argc > 1) {
		printf("command takes no or one argument\n");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->addr, args->key, "conf-read", KNOT_RRTYPE_TXT,
	                  args->argc, args->argv);
}

static int cmd_conf_begin(cmd_args_t *args)
{
	if (args->argc > 0) {
		printf("command does not take arguments\n");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->addr, args->key, "conf-begin", KNOT_RRTYPE_TXT,
	                  0, NULL);
}

static int cmd_conf_commit(cmd_args_t *args)
{
	if (args->argc > 0) {
		printf("command does not take arguments\n");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->addr, args->key, "conf-commit", KNOT_RRTYPE_TXT,
	                  0, NULL);
}

static int cmd_conf_abort(cmd_args_t *args)
{
	if (args->argc > 0) {
		printf("command does not take arguments\n");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->addr, args->key, "conf-abort", KNOT_RRTYPE_TXT,
	                  0, NULL);
}

static int cmd_conf_diff(cmd_args_t *args)
{
	if (args->argc > 1) {
		printf("command takes no or one argument\n");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->addr, args->key, "conf-diff", KNOT_RRTYPE_TXT,
	                  args->argc, args->argv);
}

static int cmd_conf_get(cmd_args_t *args)
{
	if (args->argc > 1) {
		printf("command takes no or one argument\n");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->addr, args->key, "conf-get", KNOT_RRTYPE_TXT,
	                  args->argc, args->argv);
}

static int cmd_conf_set(cmd_args_t *args)
{
	if (args->argc < 1 || args->argc > 255) {
		printf("command takes one or up to 255 arguments\n");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->addr, args->key, "conf-set", KNOT_RRTYPE_TXT,
	                  args->argc, args->argv);
}

static int cmd_conf_unset(cmd_args_t *args)
{
	if (args->argc > 255) {
		printf("command doesn't take more than 255 arguments\n");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->addr, args->key, "conf-unset", KNOT_RRTYPE_TXT,
	                  args->argc, args->argv);
}

static int cmd_checkconf(cmd_args_t *args)
{
	UNUSED(args);

	log_info("configuration is valid");

	return 0;
}

static bool fetch_zone(int argc, char *argv[], const knot_dname_t *name)
{
	bool found = false;

	int i = 0;
	while (!found && i < argc) {
		/* Convert the argument to dname */
		knot_dname_t *arg_name = knot_dname_from_str_alloc(argv[i]);

		if (arg_name != NULL) {
			(void)knot_dname_to_lower(arg_name);
			found = knot_dname_is_equal(name, arg_name);
		}

		i++;
		knot_dname_free(&arg_name, NULL);
	}

	return found;
}

static int cmd_checkzone(cmd_args_t *args)
{
	/* Zone checking */
	int rc = 0;

	/* Generate databases for all zones */
	for (conf_iter_t iter = conf_iter(conf(), C_ZONE); iter.code == KNOT_EOK;
	     conf_iter_next(conf(), &iter)) {
		conf_val_t id = conf_iter_id(conf(), &iter);

		/* Fetch zone */
		bool match = fetch_zone(args->argc, args->argv, conf_dname(&id));
		if (!match && args->argc > 0) {
			continue;
		}

		/* Create zone loader context. */
		zone_contents_t *contents = zone_load_contents(conf(), conf_dname(&id));
		if (contents == NULL) {
			rc = 1;
			continue;
		}
		zone_contents_deep_free(&contents);

		log_zone_info(conf_dname(&id), "zone is valid");
	}

	return rc;
}

static int cmd_memstats(cmd_args_t *args)
{
	/* Zone checking */
	double total_size = 0;

	/* Generate databases for all zones */
	for (conf_iter_t iter = conf_iter(conf(), C_ZONE); iter.code == KNOT_EOK;
	     conf_iter_next(conf(), &iter)) {
		conf_val_t id = conf_iter_id(conf(), &iter);

		/* Fetch zone */
		bool match = fetch_zone(args->argc, args->argv, conf_dname(&id));
		if (!match && args->argc > 0) {
			continue;
		}

		/* Init malloc wrapper for trie size estimation. */
		size_t malloc_size = 0;
		mm_ctx_t mem_ctx = { .ctx = &malloc_size,
		                     .alloc = estimator_malloc,
		                     .free = estimator_free };

		/* Init memory estimation context. */
		zone_estim_t est = {.node_table = hattrie_create_n(TRIE_BUCKET_SIZE, &mem_ctx),
		                    .dname_size = 0, .node_size = 0,
		                    .htable_size = 0, .rdata_size = 0,
		                    .record_count = 0 };
		if (est.node_table == NULL) {
			log_error("not enough memory");
			conf_iter_finish(conf(), &iter);
			break;
		}

		/* Create zone scanner. */
		char *zone_name = knot_dname_to_str_alloc(conf_dname(&id));
		if (zone_name == NULL) {
			log_error("not enough memory");
			hattrie_free(est.node_table);
			conf_iter_finish(conf(), &iter);
			break;
		}
		zs_scanner_t *zs = zs_scanner_create(zone_name,
		                                     KNOT_CLASS_IN, 3600,
		                                     estimator_rrset_memsize_wrap,
		                                     NULL, &est);
		free(zone_name);
		if (zs == NULL) {
			log_zone_error(conf_dname(&id), "failed to load zone");
			hattrie_free(est.node_table);
			continue;
		}

		/* Do a parser run, but do not actually create the zone. */
		char *zonefile = conf_zonefile(conf(), conf_dname(&id));
		int ret = zs_scanner_parse_file(zs, zonefile);
		free(zonefile);
		if (ret != 0) {
			log_zone_error(conf_dname(&id), "failed to parse zone");
			hattrie_apply_rev(est.node_table, estimator_free_trie_node, NULL);
			hattrie_free(est.node_table);
			zs_scanner_free(zs);
			continue;
		}

		/* Only size of ahtables inside trie's nodes is missing. */
		assert(est.htable_size == 0);
		est.htable_size = estimator_trie_htable_memsize(est.node_table);

		/* Cleanup */
		hattrie_apply_rev(est.node_table, estimator_free_trie_node, NULL);
		hattrie_free(est.node_table);

		double zone_size = ((double)(est.rdata_size +
		                   est.node_size +
		                   est.dname_size +
		                   est.htable_size +
		                   malloc_size) * ESTIMATE_MAGIC) / (1024.0 * 1024.0);

		log_zone_info(conf_dname(&id), "%zu RRs, used memory estimation is %zu MB",
		              est.record_count, (size_t)zone_size);
		zs_scanner_free(zs);
		total_size += zone_size;
	}

	if (args->argc == 0) { // for all zones
		log_info("estimated memory consumption for all zones is %zu MB",
		         (size_t)total_size);
	}

	return 0;
}
