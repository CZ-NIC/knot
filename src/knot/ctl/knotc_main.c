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

#include "knot/knot.h"
#include "common/mem.h"
#include "libknot/descriptor.h"
#include "knot/ctl/process.h"
#include "knot/ctl/remote.h"
#include "knot/conf/conf.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/zone-load.h"
#include "knot/server/tcp-handler.h"
#include "libknot/packet/wire.h"
#include "knot/ctl/estimator.h"

/*! \brief Controller flags. */
enum knotc_flag_t {
	F_NULL =         0 << 0,
	F_FORCE =        1 << 0,
	F_VERBOSE =      1 << 1,
	F_NOCONF =       1 << 2
};

/*! \brief Check if flag is present. */
static inline unsigned has_flag(unsigned flags, enum knotc_flag_t f)
{
	return flags & f;
}

/*! \brief Callback prototype for command. */
typedef int (*knot_cmdf_t)(int argc, char *argv[], unsigned flags);

/*! \brief Command table item. */
typedef struct knot_cmd {
	knot_cmdf_t cb;
	int need_conf;
	const char *name;
	const char *params;
	const char *desc;
} knot_cmd_t;

/* Forward decls. */
static int cmd_stop(int argc, char *argv[], unsigned flags);
static int cmd_reload(int argc, char *argv[], unsigned flags);
static int cmd_refresh(int argc, char *argv[], unsigned flags);
static int cmd_flush(int argc, char *argv[], unsigned flags);
static int cmd_status(int argc, char *argv[], unsigned flags);
static int cmd_zonestatus(int argc, char *argv[], unsigned flags);
static int cmd_checkconf(int argc, char *argv[], unsigned flags);
static int cmd_checkzone(int argc, char *argv[], unsigned flags);
static int cmd_memstats(int argc, char *argv[], unsigned flags);
static int cmd_signzone(int argc, char *argv[], unsigned flags);

/*! \brief Table of remote commands. */
knot_cmd_t knot_cmd_tbl[] = {
	{&cmd_stop,       0, "stop",       "",       "\t\tStop server."},
	{&cmd_reload,     0, "reload",     "<zone>", "\tReload configuration and changed zones."},
	{&cmd_refresh,    0, "refresh",    "<zone>", "\tRefresh slave zone (all if not specified). Flag '-f' forces retransfer."},
	{&cmd_flush,      0, "flush",      "<zone>", "\tFlush journal and update zone file (all if not specified)."},
	{&cmd_status,     0, "status",     "",       "\tCheck if server is running."},
	{&cmd_zonestatus, 0, "zonestatus", "",       "\tShow status of configured zones."},
	{&cmd_checkconf,  1, "checkconf",  "",       "\tCheck current server configuration."},
	{&cmd_checkzone,  1, "checkzone",  "<zone>", "Check zone (all if not specified)."},
	{&cmd_memstats,   1, "memstats",   "<zone>", "Estimate memory use for zone (all if not specified)."},
	{&cmd_signzone,   0, "signzone",   "<zone>", "Sign all zones with available DNSSEC keys."},
	{NULL, 0, NULL, NULL, NULL}
};

/*! \brief Print help. */
void help(void)
{
	printf("Usage: %sc [parameters] <action>\n", PACKAGE_NAME);
	printf("\nParameters:\n"
	       " -c, --config <file>    \tSelect configuration file.\n"
	       " -s <server>            \tRemote UNIX socket/IP address (default %s).\n"
	       " -p <port>              \tRemote server port (only for IP).\n"
	       " -y <[hmac:]name:key>   \tUse key specified on the command line.\n"
	       " -k <file>              \tUse key file (as in config section 'keys').\n"
	       " -f, --force            \tForce operation - override some checks.\n"
	       " -v, --verbose          \tVerbose mode - additional runtime information.\n"
	       " -V, --version          \tPrint %s server version.\n"
	       " -h, --help             \tPrint help and usage.\n",
	       RUN_DIR "/knot.sock", PACKAGE_NAME);
	printf("\nActions:\n");
	knot_cmd_t *c = knot_cmd_tbl;
	while (c->name != NULL) {
		printf(" %s %s\t\t%s\n", c->name, c->params, c->desc);
		++c;
	}
}

static int cmd_remote_print_reply(const knot_rrset_t *rr)
{
	/* Process first RRSet in data section. */
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

static int cmd_remote_reply(int c)
{
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (!pkt) {
		return KNOT_ENOMEM;
	}

	/* Read response packet. */
	int n = tcp_recv_msg(c, pkt->wire, pkt->max_size, NULL);
	if (n <= 0) {
		dbg_server("remote: couldn't receive response = %s\n", knot_strerror(n));
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
			ret = cmd_remote_print_reply(&authority->rr[0]);
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

static int cmd_remote(const char *cmd, uint16_t rrt, int argc, char *argv[])
{
	int rc = 0;

	/* Check remote address. */
	conf_iface_t *r = conf()->ctl.iface;
	if (!r || r->addr.ss_family == AF_UNSPEC) {
		log_error("no remote address for '%s' configured", cmd);
		return 1;
	}

	/* Make query. */
	knot_pkt_t *pkt = remote_query(cmd, r->key);
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
		for (int i = 0; i < argc; ++i) {
			switch(rrt) {
			case KNOT_RRTYPE_NS:
				remote_create_ns(&rr, argv[i]);
				break;
			case KNOT_RRTYPE_TXT:
			default:
				remote_create_txt(&rr, argv[i], strlen(argv[i]));
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

	if (r->key) {
		int res = remote_query_sign(pkt->wire, &pkt->size, pkt->max_size, r->key);
		if (res != KNOT_EOK) {
			log_error("failed to sign the packet");
			knot_pkt_free(&pkt);
			return 1;
		}
	}

	dbg_server("%s: sending query size %zu\n", __func__, pkt->size);

	/* Connect to remote. */
	char addr_str[SOCKADDR_STRLEN] = {0};
	sockaddr_tostr(&r->addr, addr_str, sizeof(addr_str));

	int s = net_connected_socket(SOCK_STREAM, &r->addr, &r->via, 0);
	if (s < 0) {
		log_error("failed to connect to remote host '%s'", addr_str);
		knot_pkt_free(&pkt);
		return 1;
	}

	/* Wait for availability. */
	struct pollfd pfd = { s, POLLOUT, 0 };
	if (poll(&pfd, 1, conf()->max_conn_reply) != 1) {
		log_error("failed to connect to remote host '%s'", addr_str);
		close(s);
		knot_pkt_free(&pkt);
		return 1;
	}

	/* Send and free packet. */
	int ret = tcp_send_msg(s, pkt->wire, pkt->size, NULL);
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
		ret = cmd_remote_reply(s);
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
		alg = knot_lookup_by_name(knot_tsig_alg_names, h);
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
	alg = knot_lookup_by_name(knot_tsig_alg_names, a);

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
		log_error("failed to open key-file '%s'", f);
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
				log_error("only one key definition allowed "
				          "in '%s'", f);
				ret = KNOT_EMALF;
				break;
			}
			line[llen] = '\0';
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
	int c = 0, li = 0, rc = 0;
	unsigned flags = F_NULL;
	const char *config_fn = conf_find_default();

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
		{"force", no_argument, 0, 'f'},
		{"config", required_argument, 0, 'c'},
		{"verbose", no_argument, 0, 'v'},
		{"version", no_argument, 0, 'V'},
		{"help", no_argument, 0, 'h'},
		{"server", required_argument, 0, 's' },
		{"port", required_argument, 0, 's' },
		{"y", required_argument, 0, 'y' },
		{"k", required_argument, 0, 'k' },
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "s:p:y:k:fc:vVh", opts, &li)) != -1) {
		switch (c) {
		case 's':
			r_addr = optarg;
			break;
		case 'p':
			r_port = atoi(optarg);
			break;
		case 'y':
			if (tsig_parse_str(&r_key, optarg) != KNOT_EOK) {
				rc = 1;
				log_error("failed to parse TSIG key '%s'", optarg);
				goto exit;
			}
			break;
		case 'k':
			if (tsig_parse_file(&r_key, optarg) != KNOT_EOK) {
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
		case 'c':
			config_fn = optarg;
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
		log_error("invalid command: '%s'", argv[optind]);
		rc = 1;
		goto exit;
	}

	/* Open config, create empty if not exists. */
	if (conf_open(config_fn) != KNOT_EOK) {
		s_config = conf_new("");
		flags |= F_NOCONF;
	}

	/* Check if config file is required. */
	if (has_flag(flags, F_NOCONF) && cmd->need_conf) {
		log_error("failed to find a config file, refusing to continue");
		rc = 1;
		goto exit;
	}

	/* Create remote iface if not present in config. */
	conf_iface_t *ctl_if = conf()->ctl.iface;
	if (!ctl_if) {
		ctl_if = malloc(sizeof(conf_iface_t));
		memset(ctl_if, 0, sizeof(conf_iface_t));
		conf()->ctl.iface = ctl_if;

		/* Fill defaults. */
		if (!r_addr) {
			r_addr = RUN_DIR "/knot.sock";
		} else if (r_port < 0) {
			r_port = REMOTE_DPORT;
		}
	}

	/* Install the key. */
	if (r_key.name) {
		ctl_if->key = &r_key;
	}

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

		sockaddr_set(&ctl_if->addr, family, r_addr, sockaddr_port(&ctl_if->addr));
	}

	if (r_port > 0) {
		sockaddr_port_set(&ctl_if->addr, r_port);
	}

	/* Verbose mode. */
	if (has_flag(flags, F_VERBOSE)) {
		log_levels_add(LOGT_STDOUT, LOG_ANY,
		               LOG_MASK(LOG_INFO) | LOG_MASK(LOG_DEBUG));
	}

	/* Execute command. */
	rc = cmd->cb(argc - optind - 1, argv + optind + 1, flags);

exit:
	/* Finish */
	knot_tsig_key_free(&r_key);
	log_close();
	return rc;
}

static int cmd_stop(int argc, char *argv[], unsigned flags)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(flags);

	return cmd_remote("stop", KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_reload(int argc, char *argv[], unsigned flags)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(flags);

	return cmd_remote("reload", KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_refresh(int argc, char *argv[], unsigned flags)
{
	UNUSED(flags);

	if (flags & F_FORCE) {
		return cmd_remote("retransfer", KNOT_RRTYPE_NS, argc, argv);
	} else {
		return cmd_remote("refresh", KNOT_RRTYPE_NS, argc, argv);
	}
}

static int cmd_flush(int argc, char *argv[], unsigned flags)
{
	UNUSED(flags);

	return cmd_remote("flush", KNOT_RRTYPE_NS, argc, argv);
}

static int cmd_status(int argc, char *argv[], unsigned flags)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(flags);

	return cmd_remote("status", KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_zonestatus(int argc, char *argv[], unsigned flags)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(flags);

	return cmd_remote("zonestatus", KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_signzone(int argc, char *argv[], unsigned flags)
{
	return cmd_remote("signzone", KNOT_RRTYPE_NS, argc, argv);
}

static int cmd_checkconf(int argc, char *argv[], unsigned flags)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(flags);

	log_info("configuration is valid");

	return 0;
}

static bool fetch_zone(int argc, char *argv[], conf_zone_t *zone)
{
	/* Convert zone name to dname */
	knot_dname_t *zone_name = knot_dname_from_str_alloc(zone->name);
	if (zone_name == NULL) {
		return false;
	}
	(void)knot_dname_to_lower(zone_name);

	bool found = false;

	int i = 0;
	while (!found && i < argc) {
		/* Convert the argument to dname */
		knot_dname_t *arg_name = knot_dname_from_str_alloc(argv[i]);

		if (arg_name != NULL) {
			(void)knot_dname_to_lower(arg_name);
			found = knot_dname_is_equal(zone_name, arg_name);
		}

		i++;
		knot_dname_free(&arg_name, NULL);
	}

	knot_dname_free(&zone_name, NULL);
	return found;
}

static int cmd_checkzone(int argc, char *argv[], unsigned flags)
{
	UNUSED(flags);

	/* Zone checking */
	int rc = 0;

	/* Generate databases for all zones */
	const bool sorted = false;
	hattrie_iter_t *z_iter = hattrie_iter_begin(conf()->zones, sorted);
	if (z_iter == NULL) {
		return KNOT_ERROR;
	}
	for (; !hattrie_iter_finished(z_iter); hattrie_iter_next(z_iter)) {
		conf_zone_t *zone = (conf_zone_t *)*hattrie_iter_val(z_iter);

		/* Fetch zone */
		int zone_match = fetch_zone(argc, argv, zone);

		if (!zone_match && argc > 0) {
			conf_free_zone(zone);
			continue;
		}

		/* Create zone loader context. */
		zone_contents_t *loaded_zone = zone_load_contents(zone);
		if (loaded_zone == NULL) {
			rc = 1;
			continue;
		}

		log_zone_str_info(zone->name, "zone is valid");
		zone_contents_deep_free(&loaded_zone);
	}
	hattrie_iter_free(z_iter);

	return rc;
}

static int cmd_memstats(int argc, char *argv[], unsigned flags)
{
	UNUSED(flags);

	/* Zone checking */
	double total_size = 0;

	/* Generate databases for all zones */
	const bool sorted = false;
	hattrie_iter_t *z_iter = hattrie_iter_begin(conf()->zones, sorted);
	if (z_iter == NULL) {
		return KNOT_ERROR;
	}
	for (; !hattrie_iter_finished(z_iter); hattrie_iter_next(z_iter)) {
		conf_zone_t *zone = (conf_zone_t *)*hattrie_iter_val(z_iter);

		/* Fetch zone */
		int zone_match = fetch_zone(argc, argv, zone);

		if (!zone_match && argc > 0) {
			conf_free_zone(zone);
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
			break;
		}

		/* Create zone scanner. */
		zs_scanner_t *zs = zs_scanner_create(zone->name,
		                                     KNOT_CLASS_IN, 3600,
		                                     estimator_rrset_memsize_wrap,
		                                     process_error,
		                                     &est);
		if (zs == NULL) {
			log_zone_str_error(zone->name, "failed to load zone");
			hattrie_free(est.node_table);
			continue;
		}

		/* Do a parser run, but do not actually create the zone. */
		int ret = zs_scanner_parse_file(zs, zone->file);
		if (ret != 0) {
			log_zone_str_error(zone->name, "failed to parse zone");
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

		log_zone_str_info(zone->name, "%zu RRs, used memory estimation is %zu MB",
		                  est.record_count, (size_t)zone_size);
		zs_scanner_free(zs);
		total_size += zone_size;
		conf_free_zone(zone);
	}
	hattrie_iter_free(z_iter);

	if (argc == 0) { // for all zones
		log_info("estimated memory consumption for all zones is %zu MB",
		         (size_t)total_size);
	}

	return 0;
}
