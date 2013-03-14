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

#include "common/lists.h"		// list
#include "common/errcode.h"		// KNOT_EOK
#include "common/descriptor_new.h"	// KNOT_CLASS_IN
#include "utils/common/msg.h"		// WARN
#include "utils/common/params.h"	// parse_class
#include "utils/common/resolv.h"	// get_nameservers

#define DEFAULT_RETRIES_DIG	3
#define DEFAULT_TIMEOUT_DIG	5

static const flags_t DEFAULT_FLAGS = {
	.aa_flag = false,
	.tc_flag = false,
	.rd_flag = true,
	.ra_flag = false,
	.z_flag  = false,
	.ad_flag = false,
	.cd_flag = false,
	.do_flag = false
};

static const style_t DEFAULT_STYLE = {
	.format = FORMAT_FULL,
	.style = { .wrap = false, .show_class = true, .show_ttl = true,
	           .verbose = true, .reduce = false },
	.show_header = true,
	.show_footer = true,
	.show_query = false,
	.show_question = true,
	.show_answer = true,
	.show_authority = true,
	.show_additional = true,
};

query_t* query_create(const char *owner, const query_t *conf)
{
	// Create output structure.
	query_t *query = calloc(1, sizeof(query_t));

	if (query == NULL) {
		DBG_NULL;
		return NULL;
	}

	// Set an owner if any.
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
		query->operation = OPERATION_QUERY;
		query->ip = IP_ALL;
		query->protocol = PROTO_ALL;
		query->port = strdup("");
		query->udp_size = -1;
		query->retries = DEFAULT_RETRIES_DIG;
		query->wait = DEFAULT_TIMEOUT_DIG;
		query->servfail_stop = false;
		query->class_num = -1;
		query->type_num = -1;
		query->xfr_serial = 0;
		query->flags = DEFAULT_FLAGS;
		query->style = DEFAULT_STYLE;
	} else {
		query->operation = conf->operation;
		query->ip = conf->ip;
		query->protocol = conf->protocol;
		query->port = strdup(conf->port);
		query->udp_size = conf->udp_size;
		query->retries = conf->retries;
		query->wait = conf->wait;
		query->servfail_stop = conf->servfail_stop;
		query->class_num = conf->class_num;
		query->type_num = conf->type_num;
		query->xfr_serial = conf->xfr_serial;
		query->flags = conf->flags;
		query->style = conf->style;
	}

	// Check port.
	if (query->port == NULL) {
		query_free(query);
		return NULL;
	}

	return query;
}

void query_free(query_t *query)
{
	node *n = NULL, *nxt = NULL;

	if (query == NULL) {
		DBG_NULL;
		return;
	}

	// Clean up servers.
	WALK_LIST_DELSAFE(n, nxt, query->servers) {
		server_free((server_t *)n);
	}

	free(query->owner);
	free(query->port);
	free(query);
}

int dig_init(dig_params_t *params)
{
	if (params == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	memset(params, 0, sizeof(*params));

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
	node *n = NULL, *nxt = NULL;

	if (params == NULL) {
		DBG_NULL;
		return;
	}

	// Clean up queries.
	WALK_LIST_DELSAFE(n, nxt, params->queries) {
		query_free((query_t *)n);
	}

	// Clean up config.
	query_free((query_t *)params->config);

	// Clean up the structure.
	memset(params, 0, sizeof(*params));
}

static int parse_name(const char *value, list *queries, const query_t *conf)
{
	query_t *query = NULL;

	// If name is not FQDN, append trailing dot.
	char *fqd_name = get_fqd_name(value);

	// Create new query.
	query = query_create(fqd_name, conf);

	free(fqd_name);

	if (query == NULL) {
		return KNOT_ENOMEM;
	}

	// Add new query to the queries.
	add_tail(queries, (node *)query);

	return KNOT_EOK;
}

static int parse_reverse(const char *value, list *queries, const query_t *conf)
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
	add_tail(queries, (node *)query);

	return KNOT_EOK;
}

static void complete_servers(query_t *query, const query_t *conf)
{
	node *n = NULL;
	char *def_port;

	// Decide which default port use.
	if (strlen(query->port) > 0) {
		def_port = query->port;
	} else if (strlen(conf->port) > 0) {
		def_port = conf->port;
	} else {
		def_port = DEFAULT_DNS_PORT;
	}

	// Use servers from config if any.
	if (list_size(&conf->servers) > 0) {
		server_t *server;

		WALK_LIST(n, conf->servers) {
			server_t *s = (server_t *)n;
			char     *port = def_port;

			// If the port is already specified, use it.
			if (strlen(s->service) > 0) {
				port = s->service;
			}

			server = server_create(s->name, port);

			if (server == NULL) {
				WARN("can't set nameserver %s port %s\n",
				     s->name, s->service);
				return;
			}
			add_tail(&query->servers, (node *)server);
		}
	// Use system specific.
	} else if (get_nameservers(&query->servers, def_port) <= 0) {
		WARN("can't read any nameservers\n");
	}
}

void complete_queries(list *queries, const query_t *conf)
{
	query_t *q = NULL;
	node    *n = NULL;

	if (queries == NULL || conf == NULL) {
		DBG_NULL;
		return;
	}

	// If there is no query, add default query: NS to ".".
	if (list_size(queries) == 0) {
		q = query_create(".", conf);
		if (q == NULL) {
			WARN("can't create query . NS IN\n");
			return;
		}
		q->class_num = KNOT_CLASS_IN;
		q->type_num = KNOT_RRTYPE_NS;
		add_tail(queries, (node *)q);
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

		// Fill nameserver list if empty.
		if (list_size(&q->servers) == 0) {
			complete_servers(q, conf);
		}
	}
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

static int parse_type(const char *value, query_t *query)
{
	uint16_t rtype;
	uint32_t serial;

	if (params_parse_type(value, &rtype, &serial) != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	query->type_num = rtype;
	query->xfr_serial = serial;

	return KNOT_EOK;
}

static int parse_port(const char *value, query_t *query)
{
	char **port;

	// Set current server port (last or query default).
	if (list_size(&query->servers) > 0) {
		server_t *server = TAIL(query->servers);
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

static void dig_help(const bool verbose)
{
	if (verbose == true) {
		printf("Big help\n");
	} else {
		printf("Usage: [-aCdlrsTvw] [-4] [-6] [-c class] [-R retries]\n"
		       "       [-t type] [-W time] name [server]\n");
	}
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
	case 'd':
		msg_enable_debug(1);
		break;
	case 'h':
		if (len > 1) {
			ERR("invalid option -%s\n", opt);
			return KNOT_ENOTSUP;
		}

		dig_help(true);
		return KNOT_ESTOP;;
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

	// Check for format option.
	if (strcmp(value, "multiline") == 0) {
		query->style.style.wrap = true;
	} else if (strcmp(value, "nomultiline") == 0) {
		query->style.style.wrap = false;
	}
	else if (strcmp(value, "short") == 0) {
		query->style.format = FORMAT_DIG;
	} else if (strcmp(value, "noshort") == 0) {
		query->style.format = FORMAT_FULL;
	}

	// Check for flag option.
	else if (strcmp(value, "aaflag") == 0) {
		query->flags.aa_flag = true;
	} else if (strcmp(value, "noaaflag") == 0) {
		query->flags.aa_flag = false;
	}
	else if (strcmp(value, "tcflag") == 0) {
		query->flags.tc_flag = true;
	} else if (strcmp(value, "notcflag") == 0) {
		query->flags.tc_flag = false;
	}
	else if (strcmp(value, "rdflag") == 0 ||
	         strcmp(value, "recurse") == 0) {
		query->flags.rd_flag = true;
	} else if (strcmp(value, "nordflag") == 0 ||
	           strcmp(value, "norecurse") == 0) {
		query->flags.rd_flag = false;
	}
	else if (strcmp(value, "raflag") == 0) {
		query->flags.ra_flag = true;
	} else if (strcmp(value, "noraflag") == 0) {
		query->flags.ra_flag = false;
	}
	else if (strcmp(value, "zflag") == 0) {
		query->flags.z_flag = true;
	} else if (strcmp(value, "nozflag") == 0) {
		query->flags.z_flag = false;
	}
	else if (strcmp(value, "adflag") == 0) {
		query->flags.ad_flag = true;
	} else if (strcmp(value, "noadflag") == 0) {
		query->flags.ad_flag = false;
	}
	else if (strcmp(value, "cdflag") == 0) {
		query->flags.cd_flag = true;
	} else if (strcmp(value, "nocdflag") == 0) {
		query->flags.cd_flag = false;
	}
	else if (strcmp(value, "dnssec") == 0) {
		query->flags.do_flag = true;
	} else if (strcmp(value, "nodnssec") == 0) {
		query->flags.do_flag = false;
	}

	// Check for display option.
	else if (strcmp(value, "all") == 0) {
		query->style.show_question = true;
		query->style.show_answer = true;
		query->style.show_authority = true;
		query->style.show_additional = true;
	} else if (strcmp(value, "noall") == 0) {
		query->style.show_query = false;
		query->style.show_question = false;
		query->style.show_answer = false;
		query->style.show_authority = false;
		query->style.show_additional = false;
	}
	else if (strcmp(value, "qr") == 0) {
		query->style.show_query = true;
	} else if (strcmp(value, "noqr") == 0) {
		query->style.show_query = false;
	}
	else if (strcmp(value, "question") == 0) {
		query->style.show_question = true;
	} else if (strcmp(value, "noquestion") == 0) {
		query->style.show_question = false;
	}
	else if (strcmp(value, "answer") == 0) {
		query->style.show_answer = true;
	} else if (strcmp(value, "noanswer") == 0) {
		query->style.show_answer = false;
	}
	else if (strcmp(value, "authority") == 0) {
		query->style.show_authority = true;
	} else if (strcmp(value, "noauthority") == 0) {
		query->style.show_authority = false;
	}
	else if (strcmp(value, "additional") == 0) {
		query->style.show_additional = true;
	} else if (strcmp(value, "noadditional") == 0) {
		query->style.show_additional = false;
	}
	else if (strcmp(value, "cl") == 0) {
		query->style.style.show_class = true;
	} else if (strcmp(value, "nocl") == 0) {
		query->style.style.show_class = false;
	}
	else if (strcmp(value, "ttl") == 0) {
		query->style.style.show_ttl = true;
	} else if (strcmp(value, "nottl") == 0) {
		query->style.style.show_ttl = false;
	}
	else if (strncmp(value, "time=", 5) == 0) {
		if (params_parse_wait(value + 5, &query->wait)
		    != KNOT_EOK) {
			return KNOT_EINVAL;
		}
	}
	else if (strncmp(value, "tries=", 6) == 0) {
		if (params_parse_num(value + 6, &query->retries)
		    != KNOT_EOK) {
			return KNOT_EINVAL;
		}
	}
	else if (strncmp(value, "bufsize=", 8) == 0) {
		if (params_parse_bufsize(value + 8, &query->udp_size)
		    != KNOT_EOK) {
			return KNOT_EINVAL;
		}
	}

	// Check for connection option.
	else if (strcmp(value, "tcp") == 0) {
		query->protocol = PROTO_TCP;
	} else if (strcmp(value, "notcp") == 0) {
		query->protocol = PROTO_UDP;
	}
	else if (strcmp(value, "fail") == 0) {
		query->servfail_stop = true;
	} else if (strcmp(value, "nofail") == 0) {
		query->servfail_stop = false;
	}

	// Unknown option.
	else {
		ERR("invalid option: +%s\n", value);
		return KNOT_ENOTSUP;
	}

	return KNOT_EOK;
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
	return KNOT_ENOTSUP;
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
			break;
		case KNOT_ENOTSUP:
			dig_help(false);
		default: // Fall through.
			return ret;
		}
	}

	// Complete missing data in queries based on defaults.
	complete_queries(&params->queries, params->config);

	return KNOT_EOK;
}
