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

query_t* query_create(const char *name, const uint16_t type)
{
	if (name == NULL) {
		return NULL;
	}

	// Create output structure.
	query_t *query = calloc(1, sizeof(query_t));

	// Check output.
	if (query == NULL) {
		return NULL;
	}

	// Fill output.
	query->name = strdup(name);
	query->type = type;
	query->xfr_serial = 0;

	return query;
}

void query_set_serial(query_t *query, const uint32_t serial)
{
	if (query == NULL) {
		return;
	}

	query->xfr_serial = serial;
}

void query_free(query_t *query)
{
	if (query == NULL) {
		return;
	}

	free(query->name);
	free(query);
}

static int dig_params_init(params_t *params)
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
	params->class_num = KNOT_CLASS_IN;
	params->type_num = KNOT_RRTYPE_A;
	params->xfr_serial = 0;
	params->retries = DEFAULT_RETRIES_DIG;
	params->wait = DEFAULT_TIMEOUT_DIG;
	params->servfail_stop = false;
	params->format = FORMAT_VERBOSE;

	// Initialize list of queries.
	init_list(&ext_params->queries);

	// Extended params.
	ext_params->rd_flag = true;

	return KNOT_EOK;
}

void dig_params_clean(params_t *params)
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

/*
static void dig_params_flag_soa(params_t *params)
{
	params->type_num = KNOT_RRTYPE_SOA;
	params->operation = OPERATION_LIST_SOA;
}
*/
/*
static int dig_params_parse_name(params_t *params, const char *name)
{
	char	*reverse = get_reverse_name(name);
	char	*fqd_name = NULL;
	query_t	*query;

	dig_params_t *ext_params = DIG_PARAM(params);

	// If name is not FQDN, append trailing dot.
	fqd_name = get_fqd_name(name);

	// RR type is known.
	if (params->type_num >= 0) {
		if (params->type_num == KNOT_RRTYPE_PTR) {
			// Check for correct address.
			if (reverse == NULL) {
				ERR("invalid IPv4 or IPv6 address\n");
				free(fqd_name);
				return KNOT_EINVAL;
			}

			// Add reverse query for address.
			query = query_create(reverse, params->type_num);
			if (query == NULL) {
				free(reverse);
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			add_tail(&ext_params->queries, (node *)query);
		} else {
			// Add query for name and specified type.
			query = query_create(fqd_name, params->type_num);
			if (query == NULL) {
				free(reverse);
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			// Set SOA serial for IXFR query.
			if (params->type_num == KNOT_RRTYPE_IXFR) {
				query_set_serial(query, params->xfr_serial);
			}
			add_tail(&ext_params->queries, (node *)query);
		}
	// RR type is unknown, use defaults.
	} else {
		if (reverse == NULL) {
			// Add query for name and type A.
			query = query_create(fqd_name, KNOT_RRTYPE_A);
			if (query == NULL) {
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			add_tail(&ext_params->queries, (node *)query);

			// Add query for name and type AAAA.
			query = query_create(fqd_name, KNOT_RRTYPE_AAAA);
			if (query == NULL) {
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			add_tail(&ext_params->queries, (node *)query);

			// Add query for name and type MX.
			query = query_create(fqd_name, KNOT_RRTYPE_MX);
			if (query == NULL) {
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			add_tail(&ext_params->queries, (node *)query);
		} else {
			// Add reverse query for address.
			query = query_create(reverse, KNOT_RRTYPE_PTR);
			if (query == NULL) {
				free(reverse);
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			add_tail(&ext_params->queries, (node *)query);
		}
	}

	free(reverse);
	free(fqd_name);

	return KNOT_EOK;
}*/

static int dig_params_parse_name(const char *value, params_t *params)
{
	query_t	*query;
	char    *fqd_name = NULL;

	// If name is not FQDN, append trailing dot.
	fqd_name = get_fqd_name(value);

	// Add name to query list.
	query = query_create(fqd_name, params->type_num);
	if (query == NULL) {
		free(fqd_name);
		return KNOT_ENOMEM;
	}
	add_tail(&DIG_PARAM(params)->queries, (node *)query);

	free(fqd_name);

	return KNOT_EOK;
}

static int dig_params_parse_reverse(const char *value, list *queries)
{
	char	*reverse = get_reverse_name(value);
	query_t	*query;

	// Check reverse input.
	if (reverse == NULL) {
		ERR("invalid IPv4 or IPv6 address\n");
		return KNOT_EINVAL;
	}

	// Add reverse query for address.
	query = query_create(reverse, KNOT_RRTYPE_PTR);
	if (query == NULL) {
		free(reverse);
		return KNOT_ENOMEM;
	}
	add_tail(queries, (node *)query);

	free(reverse);

	return KNOT_EOK;
}

static void set_default_query(list *queries)
{
	query_t	*query;

	// Add default query: NS to ".".
	query = query_create(".", KNOT_RRTYPE_NS);
	if (query == NULL) {
		return;
	}
	add_tail(queries, (node *)query);
}

static void dig_params_help(int argc, char *argv[])
{
	printf("Usage: %s [-aCdlrsTvw] [-4] [-6] [-c class] [-R retries]\n"
	       "       %*c [-t type] [-W time] name [server]\n",
	       argv[0], (int)strlen(argv[0]), ' ');
}

void dig_params_flag_norecurse(params_t *params)
{
	if (params == NULL) {
		return;
	}

	DIG_PARAM(params)->rd_flag = false;
}

int dig_params_parse(params_t *params, int argc, char *argv[])
{
	int opt = 0;

	if (params == NULL || argv == NULL) {
		return KNOT_EINVAL;
	}

	if (dig_params_init(params) != KNOT_EOK) {
		return KNOT_ERROR;
	}

	dig_params_t *ext_params = DIG_PARAM(params);

	// Command line options processing.
	while ((opt = getopt(argc, argv, "46c:q:t:x:")) != -1) {
		switch (opt) {
		case '4':
			params_flag_ipv4(params);
			break;
		case '6':
			params_flag_ipv6(params);
			break;
		case 'c':
			if (params_parse_class(optarg, &params->class_num)
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			break;
		case 'q':
			if (dig_params_parse_name(optarg, params)
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			break;
		case 't':
			if (params_parse_type(optarg, &params->type_num,
			                      &params->xfr_serial)
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			break;
		case 'x':
			if (dig_params_parse_reverse(optarg,
			                             &ext_params->queries)
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			break;
		default:
			dig_params_help(argc, argv);
			return KNOT_ENOTSUP;
		}
	}

	// Process non-option parameters.
	for (int i = optind; i < argc; i++) {
		switch (argv[i][0]) {
		case '@':
			if (params_parse_server(argv[i] + 1, &params->servers,
			                        params->port)
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			break;
		case '+':

			break;
		default:
			break;
		}
	}

	// If server list is empty, try to read defaults.
	if (list_size(&params->servers) == 0 &&
	    get_nameservers(&params->servers, params->port) <= 0) {
		WARN("can't read any default nameservers\n");
	}

	// If there is no query, add default one.
	if (list_size(&ext_params->queries) == 0) {
	    set_default_query(&ext_params->queries);
	}

	return KNOT_EOK;
}

