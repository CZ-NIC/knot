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

#include "utils/host/host_params.h"

#include <string.h>			// strncmp
#include <stdio.h>			// printf
#include <getopt.h>			// getopt
#include <stdlib.h>			// free

#include "common/lists.h"		// list
#include "common/errcode.h"		// KNOT_EOK
#include "libknot/util/descriptor.h"	// KNOT_CLASS_IN
#include "utils/common/msg.h"		// WARN
#include "utils/dig/dig_params.h"	// dig_params_t
#include "utils/common/resolv.h"	// get_nameservers

#define DEFAULT_RETRIES_HOST	1
#define DEFAULT_TIMEOUT_HOST	1

static int host_init(dig_params_t *params)
{
	memset(params, 0, sizeof(*params));

	// Initialize servers and queries lists.
	init_list(&params->servers);
	init_list(&params->queries);

	// Default settings.
	params->operation = OPERATION_QUERY;
	params->ip = IP_ALL;
	params->protocol = PROTO_ALL;
	params->port = strdup(DEFAULT_DNS_PORT);
	params->udp_size = DEFAULT_UDP_SIZE;
	params->retries = DEFAULT_RETRIES_HOST;
	params->wait = DEFAULT_TIMEOUT_HOST;
	params->servfail_stop = false;
	params->class_num = KNOT_CLASS_IN;
	params->type_num = -1;
	params->xfr_serial = 0;

	// Default flags.
	params->flags = DEFAULT_FLAGS;

	// Default style.
	params->style = DEFAULT_STYLE;
	params->style.format = FORMAT_HOST;

	return KNOT_EOK;
}

void host_clean(dig_params_t *params)
{
	node *n = NULL, *nxt = NULL;

	if (params == NULL) {
		return;
	}

	// Clean up servers.
	WALK_LIST_DELSAFE(n, nxt, params->servers) {
		server_free((server_t *)n);
	}

	// Clean up queries.
	WALK_LIST_DELSAFE(n, nxt, params->queries) {
		query_free((query_t *)n);
	}

	free(params->port);

	// Clean up the structure.
	memset(params, 0, sizeof(*params));
}

static int host_parse_name(const char *name, dig_params_t *params)
{
	char	*reverse = get_reverse_name(name);
	char	*fqd_name = NULL;
	query_t	*query;

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
			query = query_create(reverse, params->type_num,
			                     params->class_num);
			if (query == NULL) {
				free(reverse);
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			query->flags = params->flags;
			query->style = params->style;
			add_tail(&params->queries, (node *)query);
		} else {
			// Add query for name and specified type.
			query = query_create(fqd_name, params->type_num,
			                     params->class_num);
			if (query == NULL) {
				free(reverse);
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			// Set SOA serial for IXFR query.
			if (params->type_num == KNOT_RRTYPE_IXFR) {
				query->xfr_serial = params->xfr_serial;
			}
			query->flags = params->flags;
			query->style = params->style;
			add_tail(&params->queries, (node *)query);
		}
	// RR type is unknown, use defaults.
	} else {
		if (reverse == NULL) {
			// Add query for name and type A.
			query = query_create(fqd_name, KNOT_RRTYPE_A,
			                     params->class_num);
			if (query == NULL) {
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			query->flags = params->flags;
			query->style = params->style;
			add_tail(&params->queries, (node *)query);

			// Add query for name and type AAAA.
			query = query_create(fqd_name, KNOT_RRTYPE_AAAA,
			                     params->class_num);
			if (query == NULL) {
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			query->flags = params->flags;
			query->style = params->style;
			add_tail(&params->queries, (node *)query);

			// Add query for name and type MX.
			query = query_create(fqd_name, KNOT_RRTYPE_MX,
			                     params->class_num);
			if (query == NULL) {
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			query->flags = params->flags;
			query->style = params->style;
			add_tail(&params->queries, (node *)query);
		} else {
			// Add reverse query for address.
			query = query_create(reverse, KNOT_RRTYPE_PTR,
			                     params->class_num);
			if (query == NULL) {
				free(reverse);
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			query->flags = params->flags;
			query->style = params->style;
			add_tail(&params->queries, (node *)query);
		}
	}

	free(reverse);
	free(fqd_name);

	return KNOT_EOK;
}

static void host_help(int argc, char *argv[])
{
	printf("Usage: %s [-aCdlrsTvw] [-4] [-6] [-c class] [-R retries]\n"
	       "       %*c [-t type] [-W time] name [server]\n",
	       argv[0], (int)strlen(argv[0]), ' ');
}

int host_parse(dig_params_t *params, int argc, char *argv[])
{
	int opt = 0;

	if (params == NULL || argv == NULL) {
		return KNOT_EINVAL;
	}

	if (host_init(params) != KNOT_EOK) {
		return KNOT_ERROR;
	}

	uint16_t rclass, rtype;
	uint32_t serial;

	// Command line options processing.
	while ((opt = getopt(argc, argv, "46aCdlrsTvwc:R:t:W:")) != -1) {
		switch (opt) {
		case '4':
			params->ip = IP_4;
			break;
		case '6':
			params->ip = IP_6;
			break;
		case 'a':
			params->type_num = KNOT_RRTYPE_ANY;
			params->style.format = FORMAT_VERBOSE;
			break;
		case 'C':
			params->type_num = KNOT_RRTYPE_SOA;
			params->operation = OPERATION_LIST_SOA;
			break;
		case 'd':
		case 'v': // Fall through.
			params->style.format = FORMAT_VERBOSE;
			break;
		case 'l':
			params->type_num = KNOT_RRTYPE_AXFR;
			break;
		case 'r':
			params->flags.rd_flag = false;
			break;
		case 's':
			params->servfail_stop = true;
			break;
		case 'T':
			params->protocol = PROTO_TCP;
			break;
		case 'w':
			params->wait = -1;
			break;
		case 'c':
			if (params_parse_class(optarg, &rclass) != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			params->class_num = rclass;
			break;
		case 'R':
			if (params_parse_num(optarg, &params->retries)
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			break;
		case 't':
			if (params_parse_type(optarg, &rtype, &serial)
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			params->type_num = rtype;
			params->xfr_serial = serial;
			break;
		case 'W':
			if (params_parse_interval(optarg, &params->wait)
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			break;
		default:
			host_help(argc, argv);
			return KNOT_ENOTSUP;
		}
	}

	// Process non-option parameters.
	switch (argc - optind) {
	case 2:
		if (params_parse_server(argv[optind + 1], &params->servers,
		                        params->port)
		    != KNOT_EOK) {
			ERR("invalid nameserver\n");
			return KNOT_EINVAL;
		}
	case 1: // Fall through.
		if (host_parse_name(argv[optind], params)
		    != KNOT_EOK) {
			return KNOT_EINVAL;
		}
		break;
	default:
		host_help(argc, argv);
		return KNOT_ENOTSUP;
	}

	// If server list is empty, try to read defaults.
	if (list_size(&params->servers) == 0 &&
	    get_nameservers(&params->servers, params->port) <= 0) {
		WARN("can't read any default nameservers\n");
	}

	return KNOT_EOK;
}

