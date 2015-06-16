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

#include "utils/dig/dig_params.h"

#include <string.h>			// strncmp
#include <stdio.h>			// printf
#include <getopt.h>			// getopt
#include <stdlib.h>			// free
#include <locale.h>			// setlocale
#include <arpa/inet.h>			// inet_pton

#include "common-knot/lists.h"		// list
#include "libknot/errcode.h"		// KNOT_EOK
#include "libknot/descriptor.h"		// KNOT_CLASS_IN
#include "common-knot/sockaddr.h"	// IPV4_PREFIXLEN
#include "utils/common/msg.h"		// WARN
#include "utils/common/params.h"	// parse_class
#include "utils/common/resolv.h"	// get_nameservers

#define DEFAULT_RETRIES_DIG	2
#define DEFAULT_TIMEOUT_DIG	5

static const flags_t DEFAULT_FLAGS_DIG = {
	.aa_flag = false,
	.tc_flag = false,
	.rd_flag = true,
	.ra_flag = false,
	.z_flag  = false,
	.ad_flag = false,
	.cd_flag = false,
	.do_flag = false
};

static const style_t DEFAULT_STYLE_DIG = {
	.format = FORMAT_FULL,
	.style = {
		.wrap = false,
		.show_class = true,
		.show_ttl = true,
		.verbose = false,
		.empty_ttl = false,
		.human_ttl = false,
		.human_tmstamp = true,
		.generic = false,
		.ascii_to_idn = name_to_idn
	},
	.show_query = false,
	.show_header = true,
	.show_edns = true,
	.show_question = true,
	.show_answer = true,
	.show_authority = true,
	.show_additional = true,
	.show_tsig = true,
	.show_footer = true
};

static int opt_multiline(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.wrap = true;
	q->style.format = FORMAT_FULL;
	q->style.show_header = true;
	q->style.show_edns = true;
	q->style.show_footer = true;
	q->style.style.verbose = true;

	return KNOT_EOK;
}

static int opt_nomultiline(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.wrap = false;

	return KNOT_EOK;
}

static int opt_short(const char *arg, void *query)
{
	query_t *q = query;

	q->style.format = FORMAT_DIG;
	q->style.show_header = false;
	q->style.show_edns = false;
	q->style.show_footer = false;

	return KNOT_EOK;
}

static int opt_noshort(const char *arg, void *query)
{
	query_t *q = query;

	q->style.format = FORMAT_FULL;

	return KNOT_EOK;
}

static int opt_aaflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.aa_flag = true;

	return KNOT_EOK;
}

static int opt_noaaflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.aa_flag = false;

	return KNOT_EOK;
}

static int opt_tcflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.tc_flag = true;

	return KNOT_EOK;
}

static int opt_notcflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.tc_flag = false;

	return KNOT_EOK;
}

static int opt_rdflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.rd_flag = true;

	return KNOT_EOK;
}

static int opt_nordflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.rd_flag = false;

	return KNOT_EOK;
}

static int opt_raflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.ra_flag = true;

	return KNOT_EOK;
}

static int opt_noraflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.ra_flag = false;

	return KNOT_EOK;
}

static int opt_zflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.z_flag = true;

	return KNOT_EOK;
}

static int opt_nozflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.z_flag = false;

	return KNOT_EOK;
}

static int opt_adflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.ad_flag = true;

	return KNOT_EOK;
}

static int opt_noadflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.ad_flag = false;

	return KNOT_EOK;
}

static int opt_cdflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.cd_flag = true;

	return KNOT_EOK;
}

static int opt_nocdflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.cd_flag = false;

	return KNOT_EOK;
}

static int opt_doflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.do_flag = true;

	return KNOT_EOK;
}

static int opt_nodoflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.do_flag = false;

	return KNOT_EOK;
}

static int opt_all(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_header = true;
	q->style.show_edns = true;
	q->style.show_question = true;
	q->style.show_answer = true;
	q->style.show_authority = true;
	q->style.show_additional = true;
	q->style.show_tsig = true;
	q->style.show_footer = true;

	return KNOT_EOK;
}

static int opt_noall(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_header = false;
	q->style.show_edns = false;
	q->style.show_query = false;
	q->style.show_question = false;
	q->style.show_answer = false;
	q->style.show_authority = false;
	q->style.show_additional = false;
	q->style.show_tsig = false;
	q->style.show_footer = false;

	return KNOT_EOK;
}

static int opt_qr(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_query = true;

	return KNOT_EOK;
}

static int opt_noqr(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_query = false;

	return KNOT_EOK;
}

static int opt_header(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_header = true;

	return KNOT_EOK;
}

static int opt_noheader(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_header = false;

	return KNOT_EOK;
}

static int opt_opt(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_edns = true;

	return KNOT_EOK;
}

static int opt_noopt(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_edns = false;

	return KNOT_EOK;
}

static int opt_question(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_question = true;

	return KNOT_EOK;
}

static int opt_noquestion(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_question = false;

	return KNOT_EOK;
}

static int opt_answer(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_answer = true;

	return KNOT_EOK;
}

static int opt_noanswer(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_answer = false;

	return KNOT_EOK;
}

static int opt_authority(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_authority = true;

	return KNOT_EOK;
}

static int opt_noauthority(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_authority = false;

	return KNOT_EOK;
}

static int opt_additional(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_additional = true;

	return KNOT_EOK;
}

static int opt_noadditional(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_additional = false;
	q->style.show_edns = false;
	q->style.show_tsig = false;

	return KNOT_EOK;
}

static int opt_tsig(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_tsig = true;

	return KNOT_EOK;
}

static int opt_notsig(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_tsig = false;

	return KNOT_EOK;
}

static int opt_stats(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_footer = true;

	return KNOT_EOK;
}

static int opt_nostats(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_footer = false;

	return KNOT_EOK;
}

static int opt_class(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.show_class = true;

	return KNOT_EOK;
}

static int opt_noclass(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.show_class = false;

	return KNOT_EOK;
}

static int opt_ttl(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.show_ttl = true;

	return KNOT_EOK;
}

static int opt_nottl(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.show_ttl = false;

	return KNOT_EOK;
}

static int opt_tcp(const char *arg, void *query)
{
	query_t *q = query;

	q->protocol = PROTO_TCP;

	return KNOT_EOK;
}

static int opt_notcp(const char *arg, void *query)
{
	query_t *q = query;

	q->protocol = PROTO_UDP;
	q->ignore_tc = true;

	return KNOT_EOK;
}

static int opt_fail(const char *arg, void *query)
{
	query_t *q = query;

	q->servfail_stop = true;

	return KNOT_EOK;
}

static int opt_nofail(const char *arg, void *query)
{
	query_t *q = query;

	q->servfail_stop = false;

	return KNOT_EOK;
}

static int opt_ignore(const char *arg, void *query)
{
	query_t *q = query;

	q->ignore_tc = true;

	return KNOT_EOK;
}

static int opt_noignore(const char *arg, void *query)
{
	query_t *q = query;

	q->ignore_tc = false;

	return KNOT_EOK;
}

static int opt_noidn(const char *arg, void *query)
{
	query_t *q = query;

	q->idn = false;
	q->style.style.ascii_to_idn = NULL;

	return KNOT_EOK;
}

static int opt_generic(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.generic = true;

	return KNOT_EOK;
}

static int opt_nsid(const char *arg, void *query)
{
	query_t *q = query;

	q->nsid = true;

	return KNOT_EOK;
}

static int opt_nonsid(const char *arg, void *query)
{
	query_t *q = query;

	q->nsid = false;

	return KNOT_EOK;
}

static int opt_edns(const char *arg, void *query)
{
	query_t *q = query;

	if (arg == NULL) {
		q->edns = 0;
		return KNOT_EOK;
	} else if (*arg == '\0') {
		ERR("missing edns version\n");
		return KNOT_EFEWDATA;
	} else {
		char *end;
		long long num = strtoll(arg, &end, 10);
		// Check for bad string.
		if (end == arg || *end != '\0') {
			ERR("bad +edns=%s\n", arg);
			return KNOT_EINVAL;
		}

		if (num < 0 || num > UINT8_MAX) {
			ERR("+edns=%s is out of range\n", arg);
			return KNOT_ERANGE;
		}

		q->edns = num;

		return KNOT_EOK;
	}
}

static int opt_noedns(const char *arg, void *query)
{
	query_t *q = query;

	q->edns = -1;
	q->udp_size = -1;
	q->flags.do_flag = false;
	q->nsid = false;

	return KNOT_EOK;
}

static int opt_client(const char *arg, void *query)
{
	query_t *q = query;

	struct in_addr  addr4;
	struct in6_addr addr6;

	char          *sep = NULL;
	const size_t  arg_len = strlen(arg);
	const char    *arg_end = arg + arg_len;
	char          *addr = NULL;
	size_t        addr_len = 0;

	subnet_t *subnet = calloc(sizeof(subnet_t), 1);

	// Separate address and network mask.
	if ((sep = index(arg, '/')) != NULL) {
		addr_len = sep - arg;
	} else {
		addr_len = arg_len;
	}

	// Check IP address.
	addr = strndup(arg, addr_len);
	if (inet_pton(AF_INET, addr, &addr4) == 1) {
		subnet->family = KNOT_ADDR_FAMILY_IPV4;
		memcpy(subnet->addr, &(addr4.s_addr), IPV4_PREFIXLEN / 8);
		subnet->addr_len = IPV4_PREFIXLEN / 8;
		subnet->netmask = IPV4_PREFIXLEN;
	} else if (inet_pton(AF_INET6, addr, &addr6) == 1) {
		subnet->family = KNOT_ADDR_FAMILY_IPV6;
		memcpy(subnet->addr, &(addr6.s6_addr), IPV6_PREFIXLEN / 8);
		subnet->addr_len = IPV6_PREFIXLEN / 8;
		subnet->netmask = IPV6_PREFIXLEN;
	} else {
		free(addr);
		free(subnet);
		ERR("invalid address +client=%s\n", arg);
		return KNOT_EINVAL;
	}
	free(addr);

	// Parse network mask.
	if (arg + addr_len < arg_end) {
		char *end;

		arg += addr_len + 1;
		unsigned long num = strtoul(arg, &end, 10);
		if (end == arg || *end != '\0' || num > subnet->netmask) {
			free(subnet);
			ERR("invalid network mask +client=%s\n", arg);
			return KNOT_EINVAL;
		}
		subnet->netmask = num;
	}

	free(q->subnet);
	q->subnet = subnet;

	return KNOT_EOK;
}

static int opt_time(const char *arg, void *query)
{
	query_t *q = query;

	return params_parse_wait(arg, &q->wait);
}

static int opt_retry(const char *arg, void *query)
{
	query_t *q = query;

	return params_parse_num(arg, &q->retries);
}

static int opt_bufsize(const char *arg, void *query)
{
	query_t *q = query;

	char *end;
	long long num = strtoll(arg, &end, 10);
	// Check for bad string.
	if (end == arg || *end != '\0') {
		ERR("bad +bufsize=%s\n", arg);
		return KNOT_EINVAL;
	}

	if (num > UINT16_MAX) {
		num = UINT16_MAX;
		WARN("+bufsize=%s is too big, using %lld instead\n", arg, num);
	} else if (num < 0) {
		num = 0;
		WARN("+bufsize=%s is too small, using %lld instead\n", arg, num);
	}

	// Disable EDNS if zero bufsize.
	if (num == 0) {
		q->udp_size = -1;
	} else {
		q->udp_size = num;
	}

	return KNOT_EOK;
}

static const param_t dig_opts2[] = {
	{ "multiline",    ARG_NONE,     opt_multiline },
	{ "nomultiline",  ARG_NONE,     opt_nomultiline },

	{ "short",        ARG_NONE,     opt_short },
	{ "noshort",      ARG_NONE,     opt_noshort },

	{ "aaflag",       ARG_NONE,     opt_aaflag },
	{ "noaaflag",     ARG_NONE,     opt_noaaflag },

	{ "tcflag",       ARG_NONE,     opt_tcflag },
	{ "notcflag",     ARG_NONE,     opt_notcflag },

	{ "rdflag",       ARG_NONE,     opt_rdflag },
	{ "nordflag",     ARG_NONE,     opt_nordflag },

	{ "recurse",      ARG_NONE,     opt_rdflag },
	{ "norecurse",    ARG_NONE,     opt_nordflag },

	{ "raflag",       ARG_NONE,     opt_raflag },
	{ "noraflag",     ARG_NONE,     opt_noraflag },

	{ "zflag",        ARG_NONE,     opt_zflag },
	{ "nozflag",      ARG_NONE,     opt_nozflag },

	{ "adflag",       ARG_NONE,     opt_adflag },
	{ "noadflag",     ARG_NONE,     opt_noadflag },

	{ "cdflag",       ARG_NONE,     opt_cdflag },
	{ "nocdflag",     ARG_NONE,     opt_nocdflag },

	{ "dnssec",       ARG_NONE,     opt_doflag },
	{ "nodnssec",     ARG_NONE,     opt_nodoflag },

	{ "all",          ARG_NONE,     opt_all },
	{ "noall",        ARG_NONE,     opt_noall },

	{ "qr",           ARG_NONE,     opt_qr },
	{ "noqr",         ARG_NONE,     opt_noqr },

	{ "header",       ARG_NONE,     opt_header },
	{ "noheader",     ARG_NONE,     opt_noheader },

	{ "opt",          ARG_NONE,     opt_opt },
	{ "noopt",        ARG_NONE,     opt_noopt },

	{ "question",     ARG_NONE,     opt_question },
	{ "noquestion",   ARG_NONE,     opt_noquestion },

	{ "answer",       ARG_NONE,     opt_answer },
	{ "noanswer",     ARG_NONE,     opt_noanswer },

	{ "authority",    ARG_NONE,     opt_authority },
	{ "noauthority",  ARG_NONE,     opt_noauthority },

	{ "additional",   ARG_NONE,     opt_additional },
	{ "noadditional", ARG_NONE,     opt_noadditional },

	{ "tsig",         ARG_NONE,     opt_tsig },
	{ "notsig",       ARG_NONE,     opt_notsig },

	{ "stats",        ARG_NONE,     opt_stats },
	{ "nostats",      ARG_NONE,     opt_nostats },

	{ "class",        ARG_NONE,     opt_class },
	{ "noclass",      ARG_NONE,     opt_noclass },

	{ "ttl",          ARG_NONE,     opt_ttl },
	{ "nottl",        ARG_NONE,     opt_nottl },

	{ "tcp",          ARG_NONE,     opt_tcp },
	{ "notcp",        ARG_NONE,     opt_notcp },

	{ "fail",         ARG_NONE,     opt_fail },
	{ "nofail",       ARG_NONE,     opt_nofail },

	{ "ignore",       ARG_NONE,     opt_ignore },
	{ "noignore",     ARG_NONE,     opt_noignore },

	{ "nsid",         ARG_NONE,     opt_nsid },
	{ "nonsid",       ARG_NONE,     opt_nonsid },

	{ "edns",         ARG_OPTIONAL, opt_edns },
	{ "noedns",       ARG_NONE,     opt_noedns },

	/* "idn" doesn't work since it must be called before query creation. */
	{ "noidn",        ARG_NONE,     opt_noidn },

	{ "generic",      ARG_NONE,     opt_generic },

	{ "client",       ARG_REQUIRED, opt_client },

	{ "time",         ARG_REQUIRED, opt_time },

	{ "retry",        ARG_REQUIRED, opt_retry },

	{ "bufsize",      ARG_REQUIRED, opt_bufsize },

	{ NULL }
};

query_t* query_create(const char *owner, const query_t *conf)
{
	// Create output structure.
	query_t *query = calloc(1, sizeof(query_t));

	if (query == NULL) {
		DBG_NULL;
		return NULL;
	}

	// Set the query owner if any.
	if (owner != NULL) {
		if ((query->owner = strdup(owner)) == NULL) {
			query_free(query);
			return NULL;
		}
	}

	// Initialize list of servers.
	init_list(&query->servers);

	// Initialization with defaults or with reference query.
	if (conf == NULL) {
		query->conf = NULL;
		query->local = NULL;
		query->operation = OPERATION_QUERY;
		query->ip = IP_ALL;
		query->protocol = PROTO_ALL;
		query->port = strdup("");
		query->udp_size = -1;
		query->retries = DEFAULT_RETRIES_DIG;
		query->wait = DEFAULT_TIMEOUT_DIG;
		query->ignore_tc = false;
		query->servfail_stop = true;
		query->class_num = -1;
		query->type_num = -1;
		query->xfr_serial = 0;
		query->notify = false;
		query->flags = DEFAULT_FLAGS_DIG;
		query->style = DEFAULT_STYLE_DIG;
		query->idn = true;
		query->nsid = false;
		query->edns = -1;
		query->subnet = NULL;
#if USE_DNSTAP
		query->dt_reader = NULL;
		query->dt_writer = NULL;
#endif // USE_DNSTAP
	} else {
		query->conf = conf;
		if (conf->local != NULL) {
			query->local = srv_info_create(conf->local->name,
			                               conf->local->service);
			if (query->local == NULL) {
				query_free(query);
				return NULL;
			}
		} else {
			query->local = NULL;
		}
		query->operation = conf->operation;
		query->ip = conf->ip;
		query->protocol = conf->protocol;
		query->port = strdup(conf->port);
		query->udp_size = conf->udp_size;
		query->retries = conf->retries;
		query->wait = conf->wait;
		query->ignore_tc = conf->ignore_tc;
		query->servfail_stop = conf->servfail_stop;
		query->class_num = conf->class_num;
		query->type_num = conf->type_num;
		query->xfr_serial = conf->xfr_serial;
		query->notify = conf->notify;
		query->flags = conf->flags;
		query->style = conf->style;
		query->idn = conf->idn;
		query->nsid = conf->nsid;
		query->edns = conf->edns;
		if (conf->subnet != NULL) {
			query->subnet = malloc(sizeof(subnet_t));
			if (query->subnet == NULL) {
				query_free(query);
				return NULL;
			}
			*(query->subnet) = *(conf->subnet);
		} else {
			query->subnet = NULL;
		}
#if USE_DNSTAP
		query->dt_reader = conf->dt_reader;
		query->dt_writer = conf->dt_writer;
#endif // USE_DNSTAP

		if (knot_copy_key_params(&conf->key_params, &query->key_params)
		    != KNOT_EOK) {
			query_free(query);
			return NULL;
		}
	}

	// Check dynamic allocation.
	if (query->port == NULL) {
		query_free(query);
		return NULL;
	}

	return query;
}

void query_free(query_t *query)
{
	node_t *n = NULL, *nxt = NULL;

	if (query == NULL) {
		DBG_NULL;
		return;
	}

	// Cleanup servers.
	WALK_LIST_DELSAFE(n, nxt, query->servers) {
		srv_info_free((srv_info_t *)n);
	}

	// Cleanup local address.
	if (query->local != NULL) {
		srv_info_free(query->local);
	}

	// Cleanup cryptographic content.
	free_sign_context(&query->sign_ctx);
	knot_free_key_params(&query->key_params);

#if USE_DNSTAP
	if (query->dt_reader != NULL) {
		dt_reader_free(query->dt_reader);
	}
	if (query->dt_writer != NULL) {
		// Global writer can be shared!
		if (query->conf == NULL ||
		    query->conf->dt_writer != query->dt_writer) {
			dt_writer_free(query->dt_writer);
		}
	}
#endif // USE_DNSTAP

	free(query->owner);
	free(query->port);
	free(query->subnet);
	free(query);
}

int dig_init(dig_params_t *params)
{
	if (params == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	memset(params, 0, sizeof(*params));

	params->stop = false;

	// Initialize list of queries.
	init_list(&params->queries);

	// Create config query.
	if ((params->config = query_create(NULL, NULL)) == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

void dig_clean(dig_params_t *params)
{
	node_t *n = NULL, *nxt = NULL;

	if (params == NULL) {
		DBG_NULL;
		return;
	}

	// Clean up queries.
	WALK_LIST_DELSAFE(n, nxt, params->queries) {
		query_free((query_t *)n);
	}

	// Clean up config.
	query_free(params->config);

	// Clean up the structure.
	memset(params, 0, sizeof(*params));
}

static int parse_class(const char *value, query_t *query)
{
	uint16_t rclass;

	if (params_parse_class(value, &rclass) != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	query->class_num = rclass;

	return KNOT_EOK;
}

static int parse_keyfile(const char *value, query_t *query)
{
	knot_free_key_params(&query->key_params);

	if (params_parse_keyfile(value, &query->key_params) != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int parse_local(const char *value, query_t *query)
{
	srv_info_t *local = parse_nameserver(value, "0");
	if (local == NULL) {
		return KNOT_EINVAL;
	}

	if (query->local != NULL) {
		srv_info_free(query->local);
	}

	query->local = local;

	return KNOT_EOK;
}

static int parse_name(const char *value, list_t *queries, const query_t *conf)
{
	query_t	*query = NULL;
	char	*ascii_name = (char *)value;

	if (conf->idn) {
		ascii_name = name_from_idn(value);
		if (ascii_name == NULL) {
			return KNOT_EINVAL;
		}
	}

	// If name is not FQDN, append trailing dot.
	char *fqd_name = get_fqd_name(ascii_name);

	if (conf->idn) {
		free(ascii_name);
	}

	// Create new query.
	query = query_create(fqd_name, conf);

	free(fqd_name);

	if (query == NULL) {
		return KNOT_ENOMEM;
	}

	// Add new query to the queries.
	add_tail(queries, (node_t *)query);

	return KNOT_EOK;
}

static int parse_port(const char *value, query_t *query)
{
	char **port;

	// Set current server port (last or query default).
	if (list_size(&query->servers) > 0) {
		srv_info_t *server = TAIL(query->servers);
		port = &(server->service);
	} else {
		port = &(query->port);
	}

	char *new_port = strdup(value);

	if (new_port == NULL) {
		return KNOT_ENOMEM;
	}

	// Deallocate old string.
	free(*port);

	*port = new_port;

	return KNOT_EOK;
}

static int parse_reverse(const char *value, list_t *queries, const query_t *conf)
{
	query_t *query = NULL;

	// Create reverse name.
	char *reverse = get_reverse_name(value);

	if (reverse == NULL) {
		return KNOT_EINVAL;
	}

	// Create reverse query for given address.
	query = query_create(reverse, conf);

	free(reverse);

	if (query == NULL) {
		return KNOT_ENOMEM;
	}

	// Set type for reverse query.
	query->type_num = KNOT_RRTYPE_PTR;

	// Add new query to the queries.
	add_tail(queries, (node_t *)query);

	return KNOT_EOK;
}

static int parse_server(const char *value, dig_params_t *params)
{
	query_t *query;

	// Set current query (last or config).
	if (list_size(&params->queries) > 0) {
		query = TAIL(params->queries);
	} else {
		query = params->config;
	}

	return params_parse_server(value, &query->servers, query->port);
}

static int parse_tsig(const char *value, query_t *query)
{
	knot_free_key_params(&query->key_params);

	if (params_parse_tsig(value, &query->key_params) != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int parse_type(const char *value, query_t *query)
{
	uint16_t rtype;
	uint32_t serial;
	bool     notify;

	if (params_parse_type(value, &rtype, &serial, &notify) != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	query->type_num = rtype;
	query->xfr_serial = serial;
	query->notify = notify;

	// If NOTIFY, reset default RD flag.
	if (query->notify) {
		query->flags.rd_flag = false;
	}

	return KNOT_EOK;
}

#if USE_DNSTAP
static int parse_dnstap_output(const char *value, query_t *query)
{
	if (query->dt_writer != NULL) {
		if (query->conf == NULL ||
		    query->conf->dt_writer != query->dt_writer) {
			dt_writer_free(query->dt_writer);
		}
	}

	query->dt_writer = dt_writer_create(value, "kdig " PACKAGE_VERSION);
	if (query->dt_writer == NULL) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int parse_dnstap_input(const char *value, query_t *query)
{
	// Just in case, shouldn't happen.
	if (query->dt_reader != NULL) {
		dt_reader_free(query->dt_reader);
	}

	query->dt_reader = dt_reader_create(value);
	if (query->dt_reader == NULL) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}
#endif // USE_DNSTAP

static void complete_servers(query_t *query, const query_t *conf)
{
	node_t *n = NULL;
	char *def_port;

	// Decide which default port use.
	if (strlen(query->port) > 0) {
		def_port = query->port;
	} else if (strlen(conf->port) > 0) {
		def_port = conf->port;
	} else {
		def_port = DEFAULT_DNS_PORT;
	}

	// Complete specified nameservers if any.
	if (list_size(&query->servers) > 0) {
		WALK_LIST(n, query->servers) {
			srv_info_t *s = (srv_info_t *)n;

			// If the port isn't specified yet use the default one.
			if (strlen(s->service) == 0) {
				free(s->service);
				s->service = strdup(def_port);
				if (s->service == NULL) {
					WARN("can't set port %s\n", def_port);
					return;
				}
			}
		}
	// Use servers from config if any.
	} else if (list_size(&conf->servers) > 0) {
		WALK_LIST(n, conf->servers) {
			srv_info_t *s = (srv_info_t *)n;
			char     *port = def_port;

			// If the port is already specified, use it.
			if (strlen(s->service) > 0) {
				port = s->service;
			}

			srv_info_t *server = srv_info_create(s->name, port);
			if (server == NULL) {
				WARN("can't set nameserver %s port %s\n",
				     s->name, s->service);
				return;
			}
			add_tail(&query->servers, (node_t *)server);
		}
	// Use system specific.
	} else if (get_nameservers(&query->servers, def_port) <= 0) {
		WARN("can't read any nameservers\n");
	}
}

void complete_queries(list_t *queries, const query_t *conf)
{
	node_t  *n = NULL;

	if (queries == NULL || conf == NULL) {
		DBG_NULL;
		return;
	}

	// If there is no query, add default query: NS to ".".
	if (list_size(queries) == 0) {
		query_t *q = query_create(".", conf);
		if (q == NULL) {
			WARN("can't create query . NS IN\n");
			return;
		}
		q->class_num = KNOT_CLASS_IN;
		q->type_num = KNOT_RRTYPE_NS;
		add_tail(queries, (node_t *)q);
	}

	WALK_LIST(n, *queries) {
		query_t *q = (query_t *)n;

		// Fill class number if missing.
		if (q->class_num < 0) {
			if (conf->class_num >= 0) {
				q->class_num = conf->class_num;
			} else {
				q->class_num = KNOT_CLASS_IN;
			}
		}

		// Fill type number if missing.
		if (q->type_num < 0) {
			if (conf->type_num >= 0) {
				q->type_num = conf->type_num;
				q->xfr_serial = conf->xfr_serial;
			} else {
				q->type_num = KNOT_RRTYPE_A;
			}
		}

		// Set zone transfer if any.
		if (q->type_num == KNOT_RRTYPE_AXFR ||
		    q->type_num == KNOT_RRTYPE_IXFR) {
			q->operation = OPERATION_XFR;
		}

		// No retries for TCP.
		if (q->protocol == PROTO_TCP) {
			q->retries = 0;
		}

		// Complete nameservers list.
		complete_servers(q, conf);
	}
}

static void dig_help(void)
{
	printf("Usage: kdig [-4] [-6] [-dh] [-b address] [-c class] [-p port]\n"
	       "            [-q name] [-t type] [-x address] [-k keyfile]\n"
	       "            [-y [algo:]keyname:key] [-E tapfile] [-G tapfile]\n"
	       "            name [type] [class] [@server]\n"
	       "\n"
	       "       +[no]multiline  Wrap long records to more lines.\n"
	       "       +[no]short      Show record data only.\n"
	       "       +[no]aaflag     Set AA flag.\n"
	       "       +[no]tcflag     Set TC flag.\n"
	       "       +[no]rdflag     Set RD flag.\n"
	       "       +[no]recurse    Same as +[no]rdflag\n"
	       "       +[no]raflag     Set RA flag.\n"
	       "       +[no]zflag      Set zero flag bit.\n"
	       "       +[no]adflag     Set AD flag.\n"
	       "       +[no]cdflag     Set CD flag.\n"
	       "       +[no]dnssec     Set DO flag.\n"
	       "       +[no]all        Show all packet sections.\n"
	       "       +[no]qr         Show query packet.\n"
	       "       +[no]header     Show packet header.\n"
	       "       +[no]opt        Show EDNS pseudosection.\n"
	       "       +[no]question   Show question section.\n"
	       "       +[no]answer     Show answer section.\n"
	       "       +[no]authority  Show authority section.\n"
	       "       +[no]additional Show additional section.\n"
	       "       +[no]tsig       Show TSIG pseudosection.\n"
	       "       +[no]stats      Show trailing packet statistics.\n"
	       "       +[no]class      Show DNS class.\n"
	       "       +[no]ttl        Show TTL value.\n"
	       "       +[no]tcp        Use TCP protocol.\n"
	       "       +[no]fail       Stop if SERVFAIL.\n"
	       "       +[no]ignore     Don't use TCP automatically if truncated.\n"
	       "       +[no]nsid       Request NSID.\n"
	       "       +[no]edns=N     Use EDNS (=version).\n"
	       "       +noidn          Disable IDN transformation.\n"
	       "       +generic        Use generic representation format.\n"
	       "       +client=SUBN    Set EDNS client subnet IP/prefix.\n"
	       "       +time=T         Set wait for reply interval in seconds.\n"
	       "       +retry=N        Set number of retries.\n"
	       "       +bufsize=B      Set EDNS buffer size.\n"
	       "\n"
	       "       -h, --help      Print help.\n"
	       "       -v, --version   Print program version.\n");
}

static int parse_opt1(const char *opt, const char *value, dig_params_t *params,
                      int *index)
{
	const char *val = value;
	size_t     len = strlen(opt);
	int        add = 1;
	query_t    *query;

	// Set current query (last or config).
	if (list_size(&params->queries) > 0) {
		query = TAIL(params->queries);
	} else {
		query = params->config;
	}

	// If there is no space between option and argument.
	if (len > 1) {
		val = opt + 1;
		add = 0;
	}

	switch (opt[0]) {
	case '4':
		if (len > 1) {
			ERR("invalid option -%s\n", opt);
			return KNOT_ENOTSUP;
		}

		query->ip = IP_4;
		break;
	case '6':
		if (len > 1) {
			ERR("invalid option -%s\n", opt);
			return KNOT_ENOTSUP;
		}

		query->ip = IP_6;
		break;
	case 'b':
		if (val == NULL) {
			ERR("missing address\n");
			return KNOT_EINVAL;
		}

		if (parse_local(val, query) != KNOT_EOK) {
			ERR("bad address %s\n", val);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 'd':
		msg_enable_debug(1);
		break;
	case 'h':
		if (len > 1) {
			ERR("invalid option -%s\n", opt);
			return KNOT_ENOTSUP;
		}

		dig_help();
		params->stop = true;
		break;
	case 'c':
		if (val == NULL) {
			ERR("missing class\n");
			return KNOT_EINVAL;
		}

		if (parse_class(val, query) != KNOT_EOK) {
			ERR("bad class %s\n", val);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 'k':
		if (val == NULL) {
			ERR("missing filename\n");
			return KNOT_EINVAL;
		}

		if (parse_keyfile(val, query) != KNOT_EOK) {
			ERR("bad keyfile %s\n", value);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 'p':
		if (val == NULL) {
			ERR("missing port\n");
			return KNOT_EINVAL;
		}

		if (parse_port(val, query) != KNOT_EOK) {
			ERR("bad port %s\n", value);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 'q':
		if (val == NULL) {
			ERR("missing name\n");
			return KNOT_EINVAL;
		}

		if (parse_name(val, &params->queries, params->config)
		    != KNOT_EOK) {
			ERR("bad query name %s\n", val);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 't':
		if (val == NULL) {
			ERR("missing type\n");
			return KNOT_EINVAL;
		}

		if (parse_type(val, query) != KNOT_EOK) {
			ERR("bad type %s\n", val);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 'v':
		if (len > 1) {
			ERR("invalid option -%s\n", opt);
			return KNOT_ENOTSUP;
		}

		printf(KDIG_VERSION);
		params->stop = true;
		break;
	case 'x':
		if (val == NULL) {
			ERR("missing address\n");
			return KNOT_EINVAL;
		}

		if (parse_reverse(val, &params->queries, params->config)
		    != KNOT_EOK) {
			ERR("bad reverse name %s\n", val);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 'y':
		if (val == NULL) {
			ERR("missing key\n");
			return KNOT_EINVAL;
		}

		if (parse_tsig(val, query) != KNOT_EOK) {
			ERR("bad key %s\n", value);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 'E':
#if USE_DNSTAP
		if (val == NULL) {
			ERR("missing filename\n");
			return KNOT_EINVAL;
		}

		if (parse_dnstap_output(val, query) != KNOT_EOK) {
			ERR("unable to open dnstap output file %s\n", val);
			return KNOT_EINVAL;
		}
		*index += add;
#else
		ERR("no dnstap support but -E specified\n");
		return KNOT_EINVAL;
#endif // USE_DNSTAP
		break;
	case 'G':
#if USE_DNSTAP
		if (val == NULL) {
			ERR("missing filename\n");
			return KNOT_EINVAL;
		}

		query = query_create(NULL, params->config);
		if (query == NULL) {
			return KNOT_ENOMEM;
		}

		if (parse_dnstap_input(val, query) != KNOT_EOK) {
			ERR("unable to open dnstap input file %s\n", val);
			return KNOT_EINVAL;
		}

		query->operation = OPERATION_LIST_DNSTAP;
		add_tail(&params->queries, (node_t *)query);

		*index += add;
#else
		ERR("no dnstap support but -G specified\n");
		return KNOT_EINVAL;
#endif // USE_DNSTAP
		break;
	case '-':
		if (strcmp(opt, "-help") == 0) {
			dig_help();
			params->stop = true;
		} else if (strcmp(opt, "-version") == 0) {
			printf(KDIG_VERSION);
			params->stop = true;
		} else {
			ERR("invalid option: -%s\n", opt);
			return KNOT_ENOTSUP;
		}
		break;
	default:
		ERR("invalid option: -%s\n", opt);
		return KNOT_ENOTSUP;
	}

	return KNOT_EOK;
}

static int parse_opt2(const char *value, dig_params_t *params)
{
	query_t *query;

	// Set current query (last or config).
	if (list_size(&params->queries) > 0) {
		query = TAIL(params->queries);
	} else {
		query = params->config;
	}

	// Get option name.
	const char *arg_sep = "=";
	size_t opt_len = strcspn(value, arg_sep);
	if (opt_len < 1) {
		ERR("invalid option: +%s\n", value);
		return KNOT_ENOTSUP;
	}

	// Get option argument if any.
	const char *arg = NULL;
	const char *rest = value + opt_len;
	if (strlen(rest) > 0) {
		arg = rest + strspn(rest, arg_sep);
	}

	// Check if the given option is supported.
	bool unique;
	int ret = best_param(value, opt_len, dig_opts2, &unique);
	if (ret < 0) {
		ERR("invalid option: +%s\n", value);
		return KNOT_ENOTSUP;
	} else if (!unique) {
		ERR("ambiguous option: +%s\n", value);
		return KNOT_ENOTSUP;
	}

	// Check argument presence.
	switch (dig_opts2[ret].arg) {
	case ARG_NONE:
		if (arg != NULL) {
			ERR("superfluous option argument: +%s\n", value);
			return KNOT_ENOTSUP;
		}
		break;
	case ARG_REQUIRED:
		if (arg == NULL) {
			ERR("missing argument: +%s\n", value);
			return KNOT_EFEWDATA;
		} else if (*arg == '\0') {
			ERR("empty argument: +%s\n", value);
			return KNOT_EFEWDATA;
		}
		break;
	case ARG_OPTIONAL:
		break;
	}

	// Call option handler.
	return dig_opts2[ret].handler(arg, query);
}

static int parse_token(const char *value, dig_params_t *params)
{
	query_t *query;

	// Set current query (last or config).
	if (list_size(&params->queries) > 0) {
		query = TAIL(params->queries);
	} else {
		query = params->config;
	}

	// Try to guess the meaning of the token.
	if (parse_type(value, query) == KNOT_EOK) {
		return KNOT_EOK;
	} else if (parse_class(value, query) == KNOT_EOK) {
		return KNOT_EOK;
	} else if (parse_name(value, &params->queries, params->config)
	           == KNOT_EOK) {
		return KNOT_EOK;
	}

	ERR("invalid parameter: %s\n", value);
	return KNOT_EINVAL;
}

int dig_parse(dig_params_t *params, int argc, char *argv[])
{
	if (params == NULL || argv == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Initialize parameters.
	if (dig_init(params) != KNOT_EOK) {
		return KNOT_ERROR;
	}

#ifdef LIBIDN
	// Set up localization.
	if (setlocale(LC_CTYPE, "") == NULL) {
		WARN("can't setlocale, disabling IDN\n");
		params->config->idn = false;
		params->config->style.style.ascii_to_idn = NULL;
	}
#endif

	// Command line parameters processing.
	for (int i = 1; i < argc; i++) {
		int ret = KNOT_ERROR;

		// Process parameter.
		switch (argv[i][0]) {
		case '@':
			ret = parse_server(argv[i] + 1, params);
			break;
		case '-':
			ret = parse_opt1(argv[i] + 1, argv[i + 1], params, &i);
			break;
		case '+':
			ret = parse_opt2(argv[i] + 1, params);
			break;
		default:
			ret = parse_token(argv[i], params);
			break;
		}

		// Check return.
		switch (ret) {
		case KNOT_EOK:
			if (params->stop) {
				return KNOT_EOK;
			}
			break;
		case KNOT_ENOTSUP:
			dig_help();
		default: // Fall through.
			return ret;
		}
	}

	// Complete missing data in queries based on defaults.
	complete_queries(&params->queries, params->config);

	return KNOT_EOK;
}
