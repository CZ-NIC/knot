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
#include "knot/ctl/process.h"
#include "knot/ctl/remote.h"
#include "knot/conf/conf.h"
#include "knot/zone/zone-load.h"
#include "knot/server/socket.h"
#include "knot/server/tcp-handler.h"
#include "libknot/util/wire.h"
#include "libknot/packet/query.h"
#include "libknot/packet/response.h"

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
typedef int (*knot_cmdf_t)(int argc, char *argv[], unsigned flags, int jobs);

/*! \brief Command table item. */
typedef struct knot_cmd_t {
	const char *name;
	knot_cmdf_t cb;
	const char *desc;
	int need_conf;
} knot_cmd_t;

/* Forward decls. */
static int cmd_start(int argc, char *argv[], unsigned flags, int jobs);
static int cmd_stop(int argc, char *argv[], unsigned flags, int jobs);
static int cmd_restart(int argc, char *argv[], unsigned flags, int jobs);
static int cmd_reload(int argc, char *argv[], unsigned flags, int jobs);
static int cmd_refresh(int argc, char *argv[], unsigned flags, int jobs);
static int cmd_flush(int argc, char *argv[], unsigned flags, int jobs);
static int cmd_status(int argc, char *argv[], unsigned flags, int jobs);
static int cmd_zonestatus(int argc, char *argv[], unsigned flags, int jobs);
static int cmd_checkconf(int argc, char *argv[], unsigned flags, int jobs);
static int cmd_checkzone(int argc, char *argv[], unsigned flags, int jobs);
static int cmd_compile(int argc, char *argv[], unsigned flags, int jobs);

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
	{"compile",   &cmd_compile, "Compile zone files (all if not specified).",1},
	{NULL, NULL, NULL,0}
};

/*! \brief Print help. */
void help(int argc, char **argv)
{
	printf("Usage: %sc [parameters] <action> [action_args]\n", PACKAGE_NAME);
	printf("\nParameters:\n"
	       " -c [file], --config=[file]\tSelect configuration file.\n"
	       " -j [num], --jobs=[num]    \tNumber of parallel tasks to run when compiling.\n"
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

/*!
 * \brief Check if the zone needs recompilation.
 *
 * \param db Path to zone db file.
 * \param source Path to zone source file.
 *
 * \retval KNOT_EOK if up to date.
 * \retval KNOT_ERROR if needs recompilation.
 */
static int check_zone(const char *db, const char *source)
{
	/* Check zonefile. */
	struct stat st;
	if (stat(source, &st) != 0) {
		int reason = errno;
		const char *emsg = "";
		switch (reason) {
		case EACCES:
			emsg = "Not enough permissions to access zone file '%s'.\n";
			break;
		case ENOENT:
			emsg = "Zone file '%s' doesn't exist.\n";
			break;
		default:
			emsg = "Unable to stat zone file '%s'.\n";
			break;
		}
		log_zone_error(emsg, source);
		return KNOT_ENOENT;
	}

	/* Read zonedb header. */
	zloader_t *zl = 0;
	knot_zload_open(&zl, db);
	if (!zl) {
		return KNOT_ERROR;
	}

	/* Check source files and mtime. */
	int ret = KNOT_ERROR;
	int src_changed = strcmp(source, zl->source) != 0;
	if (!src_changed && !knot_zload_needs_update(zl)) {
		ret = KNOT_EOK;
	}

	knot_zload_close(zl);
	return ret;
}

/*! \brief Zone compiler task. */
typedef struct {
	conf_zone_t *zone;
	pid_t proc;
} knotc_zctask_t;

/*! \brief Create set of watched tasks. */
static knotc_zctask_t *zctask_create(int count)
{
	if (count <= 0) {
		return 0;
	}

	knotc_zctask_t *t = malloc(count * sizeof(knotc_zctask_t));
	for (unsigned i = 0; i < count; ++i) {
		t[i].proc = -1;
		t[i].zone = 0;
	}

	return t;
}

/*! \brief Wait for single task to finish. */
static int zctask_wait(knotc_zctask_t *tasks, int count, int is_checkzone)
{
	/* Wait for children to finish. */
	int rc = 0;
	pid_t pid = pid_wait(-1, &rc);
	
	/* Find task. */
	conf_zone_t *z = 0;
	for (unsigned i = 0; i < count; ++i) {
		if (tasks[i].proc == pid) {
			tasks[i].proc = -1;     /* Invalidate. */
			z = tasks[i].zone;
			break;
		}
	}

	if (z == 0) {
		log_server_error("Failed to find zone for finished "
		                 "zone compilation process.\n");
		return 1;
	}

	/* Evaluate. */
	if (!WIFEXITED(rc)) {
		log_server_error("%s of '%s' failed, process was killed.\n",
		                 is_checkzone ? "Checking" : "Compilation",
		                 z->name);
		return 1;
	} else {
		if (rc < 0 || WEXITSTATUS(rc) != 0) {
			if (!is_checkzone) {
				log_zone_error("Compilation of "
				               "'%s' failed, knot-zcompile "
				               "return code was '%d'\n",
				               z->name, WEXITSTATUS(rc));
			}

			return 1;
		}
	}

	return 0;
}

/*! \brief Register running zone compilation process. */
static int zctask_add(knotc_zctask_t *tasks, int count, pid_t pid,
                      conf_zone_t *zone)
{
	/* Find free space. */
	for (unsigned i = 0; i < count; ++i) {
		if (tasks[i].proc == -1) {
			tasks[i].proc = pid;
			tasks[i].zone = zone;
			return 0;
		}
	}

	/* Free space not found. */
	return -1;
}

static int cmd_remote_print_reply(const knot_rrset_t *rr)
{
	/* Process first RRSet in data section. */
	if (knot_rrset_type(rr) != KNOT_RRTYPE_TXT) {
		return KNOT_EMALF;
	}
	
	const knot_rdata_t *rd = knot_rrset_rdata(rr);
	while (rd != NULL) {
		/* Skip empty nodes. */
		if (knot_rdata_item_count(rd) < 1) {
			rd = knot_rrset_rdata_next(rr, rd);
			continue;
		}

		/* Parse TXT. */
		remote_print_txt(rd);
		rd = knot_rrset_rdata_next(rr, rd);
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
	if (n < 0) {
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
		
		/* Check extra data. */
		if (knot_packet_authority_rrset_count(reply) > 0) {
			ret = cmd_remote_print_reply(reply->authority[0]);
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
	knot_rdata_t *rd = NULL;
	knot_rrset_t *rr = remote_build_rr("data.", rrt);
	for (int i = 0; i < argc; ++i) {
		switch(rrt) {
		case KNOT_RRTYPE_CNAME:
			rd = remote_create_cname(argv[i]);
			break;
		case KNOT_RRTYPE_TXT:
		default:
			rd = remote_create_txt(argv[i], strlen(argv[i]));
			break;
		}
		knot_rrset_add_rdata(rr, rd);
		rd = NULL;
	}
	remote_query_append(qr, rr);
	if (knot_packet_to_wire(qr, &buf, &buflen) != KNOT_EOK) {
		knot_rrset_deep_free(&rr, 1, 1, 1);
		knot_packet_free(&qr);
		return 1;
	}

	if (r->key) {
		remote_query_sign(buf, &buflen, qr->max_size, r->key);
	}
	
	/* Send query. */
	int s = socket_create(r->family, SOCK_STREAM);
	int conn_state = socket_connect(s, r->address, r->port);
	if (conn_state != KNOT_EOK || tcp_send(s, buf, buflen) <= 0) {
		log_server_error("Couldn't connect to remote host "
		                 " %s@%d.\n", r->address, r->port);
		rc = 1;
	}
	
	/* Wait for reply. */
	if (rc == 0) {
		int ret = KNOT_EOK;
		while (ret != KNOT_ECONN) {
			ret = cmd_remote_reply(s);
		}
		if (ret != KNOT_EOK && ret != KNOT_ECONN) {
			log_server_warning("Remote command reply: %s\n",
			                   knot_strerror(ret));
			rc = 1;
		}
	}
	
	/* Cleanup. */
	printf("\n");
	knot_rrset_deep_free(&rr, 1, 1, 1);
	
	/* Close connection. */
	socket_close(s);
	knot_packet_free(&qr);
	return rc;
}

static knot_lookup_table_t tsig_algn_tbl[] = {
	{ KNOT_TSIG_ALG_NULL,       "gss-tsig" },
	{ KNOT_TSIG_ALG_HMAC_MD5,    "hmac-md5" },
	{ KNOT_TSIG_ALG_HMAC_SHA1,   "hmac-sha1" },
	{ KNOT_TSIG_ALG_HMAC_SHA224, "hmac-sha224" },
	{ KNOT_TSIG_ALG_HMAC_SHA256, "hmac-sha256" },
	{ KNOT_TSIG_ALG_HMAC_SHA384, "hmac-sha384" },
	{ KNOT_TSIG_ALG_HMAC_SHA512, "hmac-sha512" },
	{ KNOT_TSIG_ALG_NULL, NULL }
};

static int tsig_parse_str(knot_key_t *key, const char *str)
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
	key->algorithm = KNOT_TSIG_ALG_HMAC_MD5;
	if (s) {
		*s++ = '\0';               /* Last part separator */
		knot_lookup_table_t *alg = NULL;
		alg = knot_lookup_by_name(tsig_algn_tbl, h);
		if (alg) {
			key->algorithm = alg->id;
		} else {
			free(h);
			return KNOT_EINVAL;
		}
	} else {
		s = k; /* Ignore first part, push down. */
		k = h;
	}
	
	/* Parse key name. */
	key->name = remote_dname_fqdn(k);
	key->secret = strdup(s);
	free(h);
	
	/* Check name and secret. */
	if (!key->name || !key->secret) {
		return KNOT_EINVAL;
	}
	
	return KNOT_EOK;
}

static int tsig_parse_line(knot_key_t *k, char *l)
{
	const char *n, *a, *s;
	n = a = s = NULL;
	int fw = 1; /* 0 = reading word, 1 = between words */
	while (*l != '\0') {
		if (isspace(*l) || *l == '"') {
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
	
	/* Set algorithm. */
	knot_lookup_table_t *alg = knot_lookup_by_name(tsig_algn_tbl, a);
	if (alg) {
		k->algorithm = alg->id;
	} else {
		return KNOT_EMALF;
	}
	
	/* Set name. */
	k->name = remote_dname_fqdn(n);
	k->secret = strdup(s);
	
	/* Check name and secret. */
	if (!k->name || !k->secret) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int tsig_parse_file(knot_key_t *k, const char *f)
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

static void tsig_key_cleanup(knot_key_t *k)
{
	if (k) {
		knot_dname_free(&k->name);
		free(k->secret);
	}
}

int main(int argc, char **argv)
{
	/* Parse command line arguments */
	int c = 0, li = 0;
	unsigned jobs = 1;
	unsigned flags = F_NULL;
	char *config_fn = NULL;
	char *default_config = conf_find_default();
	
	/* Remote server descriptor. */
	int ret = KNOT_EOK;
	const char *r_addr = NULL;
	int r_port = -1;
	knot_key_t r_key;
	memset(&r_key, 0, sizeof(knot_key_t));
	
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
		{"jobs", required_argument, 0, 'j'},
		{"version", no_argument, 0, 'V'},
		{"help", no_argument, 0, 'h'},
		{"server", required_argument, 0, 's' },
		{"port", required_argument, 0, 's' },
		{"y", required_argument, 0, 'y' },
		{"k", required_argument, 0, 'k' },
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "s:p:y:k:wfc:vij:Vh", opts, &li)) != -1) {
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
				tsig_key_cleanup(&r_key);
				log_close();
				return 1;
			}
			break;
		case 'k':
			ret = tsig_parse_file(&r_key, optarg);
			if (ret != KNOT_EOK) {
				log_server_error("Couldn't parse TSIG key file "
				                 "'%s'\n", optarg);
				tsig_key_cleanup(&r_key);
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
		case 'j':
			jobs = atoi(optarg);

			if (jobs < 1) {
				log_server_error("Invalid parameter '%s' to '-j'"
				                 ", expects number <1..n>\n",
				                 optarg);
				help(argc, argv);
				log_close();
				free(config_fn);
				free(default_config);
				return 1;
			}

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
		tsig_key_cleanup(&r_key);
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
		tsig_key_cleanup(&r_key);
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
			ctl_if->key = malloc(sizeof(knot_key_t));
			if (ctl_if->key) {
				memcpy(ctl_if->key, &r_key, sizeof(knot_key_t));
			}
		}
	} else {
		if (r_key.name) {
			tsig_key_cleanup(ctl_if->key);
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
	int rc = cmd->cb(argc - optind - 1, argv + optind + 1, flags, jobs);

	/* Finish */
	tsig_key_cleanup(&r_key); /* Not cleaned by config deinit. */
	log_close();
	free(config_fn);
	free(default_config);
	return rc;
}

static int cmd_start(int argc, char *argv[], unsigned flags, int jobs)
{
	/* Check config. */
	if (has_flag(flags, F_NOCONF)) {
		log_server_error("Couldn't parse config file, refusing to "
		                 "continue.\n");
		return 1;
	}
	
	/* Alter privileges. */
	log_update_privileges(conf()->uid, conf()->gid);
	proc_update_privileges(conf()->uid, conf()->gid);
	
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
	} else {
		/* Create empty PID file. */
		FILE *f = fopen(pidfile, "w");
		if (f == NULL) {
			log_server_warning("PID file '%s' is not writeable.\n",
			                   pidfile);
			free(pidfile);
			return 1;
		}
		fclose(f);
	}
	
	/* Recompile zones if needed. */
	cmd_compile(argc, argv, flags, jobs);

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

static int cmd_stop(int argc, char *argv[], unsigned flags, int jobs)
{
	/* Check config. */
	if (has_flag(flags, F_NOCONF)) {
		log_server_error("Couldn't parse config file, refusing to "
		                 "continue.\n");
		return 1;
	}
	
	/* Alter privileges. */
	log_update_privileges(conf()->uid, conf()->gid);
	proc_update_privileges(conf()->uid, conf()->gid);
	
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

static int cmd_restart(int argc, char *argv[], unsigned flags, int jobs)
{
	/* Check config. */
	if (has_flag(flags, F_NOCONF)) {
		log_server_error("Couldn't parse config file, refusing to "
		                 "continue.\n");
		return 1;
	}
	
	int rc = 0;
	rc |= cmd_stop(argc, argv, flags | F_WAIT, jobs);
	rc |= cmd_start(argc, argv, flags, jobs);
	return rc;
}

static int cmd_reload(int argc, char *argv[], unsigned flags, int jobs)
{
	return cmd_remote("reload", KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_refresh(int argc, char *argv[], unsigned flags, int jobs)
{
	return cmd_remote("refresh", KNOT_RRTYPE_CNAME, argc, argv);
}

static int cmd_flush(int argc, char *argv[], unsigned flags, int jobs)
{
	return cmd_remote("flush", KNOT_RRTYPE_CNAME, argc, argv);
}

static int cmd_status(int argc, char *argv[], unsigned flags, int jobs)
{
	return cmd_remote("status", KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_zonestatus(int argc, char *argv[], unsigned flags, int jobs)
{
	return cmd_remote("zonestatus", KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_checkconf(int argc, char *argv[], unsigned flags, int jobs)
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

static int cmd_checkzone(int argc, char *argv[], unsigned flags, int jobs)
{
	return cmd_compile(argc, argv, flags | F_DRYRUN, jobs);
}

static int cmd_compile(int argc, char *argv[], unsigned flags, int jobs)
{
	/* Print job count */
	if (jobs > 1 && argc == 0) {
		log_server_warning("Will attempt to compile %d zones "
		                   "in parallel, this increases memory "
		                   "consumption for large zones.\n", jobs);
	}

	/* Zone checking */
	int rc = 0;
	node *n = 0;
	int running = 0;
	int is_checkzone = has_flag(flags, F_DRYRUN);
	knotc_zctask_t *tasks = zctask_create(jobs);
	
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
			continue;
		}

		/* Check source files and mtime */
		int zone_status = check_zone(zone->db, zone->file);
		if (zone_status == KNOT_EOK && !is_checkzone) {
			log_zone_info("Zone '%s' is up-to-date.\n", zone->name);
			if (has_flag(flags, F_FORCE)) {
				log_zone_info("Forcing zone "
				              "recompilation.\n");
			} else {
				continue;
			}
		}

		/* Check for not existing source */
		if (zone_status == KNOT_ENOENT) {
			continue;
		}

		/* Evaluate space for new task. */
		if (running == jobs) {
			rc |= zctask_wait(tasks, jobs, is_checkzone);
			--running;
		}

		/* Build executable command. */
		int ac = 0;
		const char *args[7] = { NULL };
		args[ac++] = ZONEPARSER_EXEC;
		if (zone->enable_checks) {
			args[ac++] = "-s";
		}
		if (has_flag(flags, F_VERBOSE)) {
			args[ac++] = "-v";
		}
		if (!is_checkzone) {
			args[ac++] = "-o";
			args[ac++] = zone->db;
		}
		args[ac++] = zone->name;
		args[ac++] = zone->file;

		/* Execute command */
		if (has_flag(flags, F_VERBOSE) && !is_checkzone) {
			log_zone_info("Compiling '%s' as '%s'...\n",
			              zone->name, zone->db);
		}
		fflush(stdout);
		fflush(stderr);
		pid_t zcpid = pid_start(args, ac,
		                        has_flag(flags, F_UNPRIVILEGED));
		zctask_add(tasks, jobs, zcpid, zone);
		++running;
	}

	/* Wait for all running tasks. */
	while (running > 0) {
		rc |= zctask_wait(tasks, jobs, is_checkzone);
		--running;
	}

	free(tasks);
	return rc;
}
