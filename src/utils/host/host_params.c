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
#include "utils/common/params.h"	// parse_class
#include "utils/common/resolv.h"	// get_nameservers
#include "utils/common/netio.h"

static void host_params_init(params_t *params)
{
	memset(params, 0, sizeof(*params));

	// Read default nameservers.
	if (get_nameservers(&params->servers) <= 0) {
		WARN("can't read any default nameservers\n");
	}

	// Initialize list of queries.
	init_list(&params->queries);

	// Default values.
	params->operation = OPERATION_QUERY;
	params->ip = IP_ALL;
	params->protocol = PROTO_ALL;
	params->udp_size = DEFAULT_UDP_SIZE;
	params->class_num = KNOT_CLASS_IN;
	params->type_num = -1;
	params->xfr_serial = -1;
	params->recursion = true;
	params->retries = 1;
	params->wait = DEFAULT_WAIT_INTERVAL;
	params->servfail_stop = false;
	params->format = FORMAT_HOST;
}

void host_params_clean(params_t *params)
{
	node *n = NULL, *nxt = NULL;

	if (params == NULL) {
		return;
	}

	// Clean up server list.
	WALK_LIST_DELSAFE(n, nxt, params->servers) {
		server_free((server_t *)n);
	}

	// Clean up query list.
	WALK_LIST_DELSAFE(n, nxt, params->queries) {
		query_free((query_t *)n);
	}

	// Clean up the structure.
	memset(params, 0, sizeof(*params));
}

static void host_params_flag_all(params_t *params)
{
	params->type_num = KNOT_RRTYPE_ANY;
	params->format = FORMAT_VERBOSE;
}

static void host_params_flag_soa(params_t *params)
{
	params->type_num = KNOT_RRTYPE_SOA;
	params->operation = OPERATION_LIST_SOA;
}

static void host_params_flag_axfr(params_t *params)
{
	params->type_num = KNOT_RRTYPE_AXFR;
}

static void host_params_flag_nonrecursive(params_t *params)
{
	params->recursion = false;
}

static void host_params_flag_ipv4(params_t *params)
{
	params->ip = IP_4;
}

static void host_params_flag_ipv6(params_t *params)
{
	params->ip = IP_6;
}

static void host_params_flag_servfail(params_t *params)
{
	params->servfail_stop = true;
}

static void host_params_flag_nowait(params_t *params)
{
	params->wait = -1;
}

static int host_params_parse_name(params_t *params, const char *name)
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
			query = query_create(reverse, params->type_num);
			if (query == NULL) {
				free(reverse);
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			add_tail(&params->queries, (node *)query);
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
			add_tail(&params->queries, (node *)query);
		}
	// RR type is unknown, use defaults.
	} else {
		if (reverse == NULL) {
			// Add query for name and type A.
			query = query_create(fqd_name, KNOT_RRTYPE_A);
			if (query == NULL) {
				free(fqd_name);
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			add_tail(&params->queries, (node *)query);

			// Add query for name and type AAAA.
			query = query_create(fqd_name, KNOT_RRTYPE_AAAA);
			if (query == NULL) {
				free(fqd_name);
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			add_tail(&params->queries, (node *)query);

			// Add query for name and type MX.
			query = query_create(fqd_name, KNOT_RRTYPE_MX);
			if (query == NULL) {
				free(fqd_name);
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			add_tail(&params->queries, (node *)query);
		} else {
			// Add reverse query for address.
			query = query_create(reverse, KNOT_RRTYPE_PTR);
			if (query == NULL) {
				free(reverse);
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			add_tail(&params->queries, (node *)query);
		}
	}

	free(reverse);
	free(fqd_name);

	return KNOT_EOK;
}

static int host_params_parse_server(params_t *params, const char *name)
{
	node *n = NULL, *nxt = NULL;

	// Remove default nameservers.
        WALK_LIST_DELSAFE(n, nxt, params->servers) {
                server_free((server_t *)n);
        }

	// Initialize blank server list.
	init_list(&params->servers);

	// Add specified nameserver.
	server_t *server = parse_nameserver(name);
	if (server == NULL) {
		return KNOT_ENOMEM;
	}
	add_tail(&params->servers, (node *)server);

	return KNOT_EOK;
}

static void host_params_help(int argc, char *argv[])
{
	// Not updated!
	printf("Usage: %s [-aCdvlrT] [-4] [-6] [-c class] [-t type] {name} [server]\n", argv[0]);
}

int host_params_parse(params_t *params, int argc, char *argv[])
{
	int opt = 0;

	if (params == NULL || argv == NULL) {
		return KNOT_EINVAL;
	}

	host_params_init(params);

	// Command line options processing.
	while ((opt = getopt(argc, argv, "aClrT46swR:W:c:t:dv")) != -1) {
		switch (opt) {
		case 'a':
			host_params_flag_all(params);
			break;
		case 'C':
			host_params_flag_soa(params);
			break;
		case 'l':
			host_params_flag_axfr(params);
			break;
		case 'r':
			host_params_flag_nonrecursive(params);
			break;
		case 'T':
			params_flag_tcp(params);
			break;
		case '4':
			host_params_flag_ipv4(params);
			break;
		case '6':
			host_params_flag_ipv6(params);
			break;
		case 's':
			host_params_flag_servfail(params);
			break;
		case 'w':
			host_params_flag_nowait(params);
			break;
		case 'R':
			if (params_parse_num(optarg, &(params->retries))
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			break;
		case 'W':
			if (params_parse_interval(optarg, &(params->wait))
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			break;
		case 'c':
			if (parse_class(optarg, &(params->class_num))
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			break;
		case 't':
			if (parse_type(optarg, &(params->type_num),
			               &(params->xfr_serial))
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			break;
		case 'd':
		case 'v': // Fall through.
			params_flag_verbose(params);
			break;
		default:
			host_params_help(argc, argv);
			return KNOT_ENOTSUP;
		}
	}

	// Process non-option parameters.
	switch (argc - optind) {
	case 2:
		if (host_params_parse_server(params, argv[optind + 1])
		    != KNOT_EOK) {
			return KNOT_EINVAL;
		}
	case 1: // Fall through.
		if (host_params_parse_name(params, argv[optind])
		    != KNOT_EOK) {
			return KNOT_EINVAL;
		}
		break;
	default:
		host_params_help(argc, argv);
		return KNOT_ENOTSUP;
	}

	return KNOT_EOK;
}

