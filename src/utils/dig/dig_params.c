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
#include "libknot/util/descriptor.h"	// KNOT_CLASS_IN
#include "utils/common/msg.h"		// WARN
#include "utils/common/params.h"	// parse_class
#include "utils/common/resolv.h"	// get_nameservers

#define DEFAULT_RETRIES_DIG	3
#define DEFAULT_TIMEOUT_DIG	5

query_t* query_create(const char    *qname,
                      const int32_t qtype,
                      const int32_t qclass)
{
	if (qname == NULL) {
		return NULL;
	}

	// Create output structure.
	query_t *query = calloc(1, sizeof(query_t));

	// Check output.
	if (query == NULL) {
		return NULL;
	}

	// Fill output.
	query->qname = strdup(qname);
	query->qclass = qclass;
	query->qtype = qtype;
	query->xfr_serial = 0;

	return query;
}

void query_free(query_t *query)
{
	if (query == NULL) {
		return;
	}

	free(query->qname);
	free(query);
}

static int dig_init(params_t *params)
{
	memset(params, 0, sizeof(*params));

	// Create dig specific data structure.
	params->d = calloc(1, sizeof(dig_params_t));
	if (!params->d) {
		return KNOT_ENOMEM;
	}
	dig_params_t *ext_params = DIG_PARAM(params);

	// Initialize blank server list.
	init_list(&params->servers);

	// Default values.
	params->operation = OPERATION_QUERY;
	params->ip = IP_ALL;
	params->protocol = PROTO_ALL;
	params->port = strdup(DEFAULT_DNS_PORT);
	params->udp_size = DEFAULT_UDP_SIZE;
	params->class_num = -1;
	params->type_num = -1;
	params->xfr_serial = 0;
	params->retries = DEFAULT_RETRIES_DIG;
	params->wait = DEFAULT_TIMEOUT_DIG;
	params->servfail_stop = false;
	params->format = FORMAT_VERBOSE;

	// Initialize list of queries.
	init_list(&ext_params->queries);

	// Extended params.
	ext_params->options.rd_flag = true;

	return KNOT_EOK;
}

void dig_clean(params_t *params)
{
	node *n = NULL, *nxt = NULL;

	if (params == NULL) {
		return;
	}

	dig_params_t *ext_params = DIG_PARAM(params);

	// Clean up server list.
	WALK_LIST_DELSAFE(n, nxt, params->servers) {
		server_free((server_t *)n);
	}

	// Clean up query list.
	WALK_LIST_DELSAFE(n, nxt, ext_params->queries) {
		query_free((query_t *)n);
	}

	free(params->port);

	// Destroy dig specific structure.
	free(ext_params);

	// Clean up the structure.
	memset(params, 0, sizeof(*params));
}

static int parse_name(const char *value, params_t *params)
{
	query_t *query = NULL;

	// If name is not FQDN, append trailing dot.
	char *fqd_name = get_fqd_name(value);

	// Create new query.
	query = query_create(fqd_name, params->type_num, params->class_num);

	free(fqd_name);

	if (query == NULL) {
		return KNOT_ENOMEM;
	}

	// Add new query to the queries.
	add_tail(&DIG_PARAM(params)->queries, (node *)query);

	return KNOT_EOK;
}

static int parse_reverse(const char *value, params_t *params)
{
	query_t *query = NULL;

	// Create reverse name.
	char *reverse = get_reverse_name(value);

	// Check reverse input.
	if (reverse == NULL) {
		return KNOT_EINVAL;
	}

	// Create reverse query for given address.
	query = query_create(reverse, KNOT_RRTYPE_PTR, params->class_num);

	free(reverse);

	if (query == NULL) {
		return KNOT_ENOMEM;
	}

	// Add new query to the queries.
	add_tail(&DIG_PARAM(params)->queries, (node *)query);

	return KNOT_EOK;
}

static void complete_queries(params_t *params)
{
	query_t *query = NULL;
	node    *n = NULL;

	dig_params_t *ext_params = DIG_PARAM(params);

	// If there is no query, add default query: NS to ".".
	if (list_size(&ext_params->queries) == 0) {
		query = query_create(".", KNOT_RRTYPE_NS, KNOT_CLASS_IN);
		if (query == NULL) {
			WARN("can't create query . NS IN\n");
			return;
		}
		add_tail(&ext_params->queries, (node *)query);
		query = NULL;
	}

	WALK_LIST(n, ext_params->queries) {
		query_t *q = (query_t *)n;

		if (q->qclass < 0) {
			if (params->class_num >= 0) {
				q->qclass = params->class_num;
			} else {
				q->qclass = KNOT_CLASS_IN;
			}
		}
		if (q->qtype < 0) {
			if (params->type_num >= 0) {
				q->qtype = params->type_num;
				q->xfr_serial = params->xfr_serial;
			} else {
				q->qtype = KNOT_RRTYPE_A;
			}
		}
	}
}

static int parse_class(const char *value, params_t *params)
{
	uint16_t rclass;

	if (params_parse_class(value, &rclass) != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	list *queries = &DIG_PARAM(params)->queries;

	// Change default.
	if (list_size(queries) == 0) {
		params->class_num = rclass;
	// Change current.
	} else {
		query_t *query = TAIL(*queries);

		query->qclass = rclass;
	}

	return KNOT_EOK;
}

static int parse_type(const char *value, params_t *params)
{
	uint16_t rtype;
	uint32_t serial;

	if (params_parse_type(value, &rtype, &serial) != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	list *queries = &DIG_PARAM(params)->queries;

	// Change default.
	if (list_size(queries) == 0) {
		params->type_num = rtype;
		params->xfr_serial = serial;
	// Change current.
	} else {
		query_t *query = TAIL(*queries);

		query->qtype = rtype;
		query->xfr_serial = serial;
	}

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

void dig_params_flag_norecurse(params_t *params)
{
	if (params == NULL) {
		return;
	}

	DIG_PARAM(params)->options.rd_flag = false;
}

static int parse_server(const char *value, params_t *params)
{
	int ret = params_parse_server(value, &params->servers, params->port);

	if (ret != KNOT_EOK) {
		ERR("invalid nameserver: %s\n", value);
	}

	return ret;
}

static int parse_opt1(const char *opt, const char *value,
                         params_t *params, int *index)
{
	const char *val = value;
	size_t     len = strlen(opt);
	int        add = 1;

	// If there is no space between option and argument.
	if (len > 1) {
		val = opt + 1;
		add = 0;
	}

	switch (opt[0]) {
	case '4':
		if (len > 1) {
			return KNOT_ENOTSUP;
		}

		params_flag_ipv4(params);
		break;
	case '6':
		if (len > 1) {
			return KNOT_ENOTSUP;
		}

		params_flag_ipv6(params);
		break;
	case 'c':
		if (val == NULL) {
			ERR("missing class\n");
			return KNOT_EINVAL;
		}

		if (parse_class(val, params) != KNOT_EOK) {
			ERR("invalid class: %s\n", val);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 'h':
		if (len > 1) {
			return KNOT_ENOTSUP;
		}

		dig_help(true);
		return KNOT_ESTOP;;
	case 'p':
		if (val == NULL) {
			ERR("missing port\n");
			return KNOT_EINVAL;
		}

		if (params_parse_port(val, &params->port)
		    != KNOT_EOK) {
			ERR("invalid port: %s\n", val);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 'q':
		if (val == NULL) {
			ERR("missing name\n");
			return KNOT_EINVAL;
		}

		if (parse_name(val, params) != KNOT_EOK) {
			ERR("invalid name: %s\n", val);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 't':
		if (val == NULL) {
			ERR("missing type\n");
			return KNOT_EINVAL;
		}

		if (parse_type(val, params) != KNOT_EOK) {
			ERR("invalid type: %s\n", val);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 'x':
		if (val == NULL) {
			ERR("missing address\n");
			return KNOT_EINVAL;
		}

		if (parse_reverse(val, params) != KNOT_EOK) {
			ERR("invalid IPv4 or IPv6 address: %s\n", val);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	default:
		ERR("unknown option: -%s\n", opt);
		return KNOT_ENOTSUP;
	}

	return KNOT_EOK;
}

static int parse_opt2(const char *value, params_t *params)
{
	ERR("invalid option: %s\n", value);

	return KNOT_EOK;
}

static int parse_token(const char *value, params_t *params)
{

	if (parse_type(value, params) == KNOT_EOK) {
		return KNOT_EOK;
	} else if (parse_class(value, params) == KNOT_EOK) {
		return KNOT_EOK;
	} else if (parse_name(value, params) == KNOT_EOK) {
		return KNOT_EOK;
	}

	ERR("invalid parameter: %s\n", value);

	return KNOT_ERROR;
}

int dig_parse(params_t *params, int argc, char *argv[])
{
	if (params == NULL || argv == NULL) {
		return KNOT_EINVAL;
	}

	// Initialize parameters.
	if (dig_init(params) != KNOT_EOK) {
		return KNOT_ERROR;
	}

	// Command line parameters processing.
	for (int i = 1; i < argc; i++) {
		int ret = KNOT_ERROR;

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

		switch (ret) {
		case KNOT_EOK:
			break;
		case KNOT_ENOTSUP:
			dig_help(false);
		default: // Fall through.
			return ret;
		}
	}

	// If server list is empty, try to read defaults.
	if (list_size(&params->servers) == 0 &&
	    get_nameservers(&params->servers, params->port) <= 0) {
		WARN("can't read any default nameservers\n");
	}

	// Complete missing data in queries based on defaults.
	complete_queries(params);

	return KNOT_EOK;
}

