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
#include "common/descriptor_new.h"	// KNOT_CLASS_IN
#include "utils/common/msg.h"		// WARN
#include "utils/dig/dig_params.h"	// dig_params_t
#include "utils/common/resolv.h"	// get_nameservers

#define DEFAULT_RETRIES_HOST	1
#define DEFAULT_TIMEOUT_HOST	1

static int host_init(dig_params_t *params)
{
	// Initialize params with dig defaults.
	int ret = dig_init(params);

	if (ret != KNOT_EOK) {
		return ret;
	}

	// Set host specific defaults.
	params->config->retries = DEFAULT_RETRIES_HOST;
	params->config->wait = DEFAULT_TIMEOUT_HOST;
	params->config->class_num = KNOT_CLASS_IN;
	params->config->style.format = FORMAT_HOST;

	return KNOT_EOK;
}

void host_clean(dig_params_t *params)
{
	if (params == NULL) {
		DBG_NULL;
		return;
	}

	dig_clean(params);
}

static int parse_name(const char *value, list *queries, const query_t *conf)
{
	char	*reverse = get_reverse_name(value);
	char	*fqd_name = NULL;
	query_t	*query;

	// If name is not FQDN, append trailing dot.
	fqd_name = get_fqd_name(value);

	// RR type is known.
	if (conf->type_num >= 0) {
		if (conf->type_num == KNOT_RRTYPE_PTR) {
			free(fqd_name);

			// Check for correct address.
			if (reverse == NULL) {
				ERR("invalid IPv4 or IPv6 address %s\n", value);
				return KNOT_EINVAL;
			}

			// Add reverse query for address.
			query = query_create(reverse, conf);
			free(reverse);
			if (query == NULL) {
				return KNOT_ENOMEM;
			}
			add_tail(queries, (node *)query);
		} else {
			free(reverse);

			// Add query for name and specified type.
			query = query_create(fqd_name, conf);
			free(fqd_name);
			if (query == NULL) {
				return KNOT_ENOMEM;
			}
			add_tail(queries, (node *)query);
		}
	// RR type is unknown, use defaults.
	} else {
		if (reverse == NULL) {
			// Add query for name and type A.
			query = query_create(fqd_name, conf);
			if (query == NULL) {
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			query->type_num = KNOT_RRTYPE_A;
			add_tail(queries, (node *)query);

			// Add query for name and type AAAA.
			query = query_create(fqd_name, conf);
			if (query == NULL) {
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			query->type_num = KNOT_RRTYPE_AAAA;
			add_tail(queries, (node *)query);

			// Add query for name and type MX.
			query = query_create(fqd_name, conf);
			if (query == NULL) {
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			free(fqd_name);
			query->type_num = KNOT_RRTYPE_MX;
			add_tail(queries, (node *)query);
		} else {
			free(fqd_name);

			// Add reverse query for address.
			query = query_create(reverse, conf);
			free(reverse);
			if (query == NULL) {
				return KNOT_ENOMEM;
			}
			query->type_num = KNOT_RRTYPE_PTR;
			add_tail(queries, (node *)query);
		}
	}

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
		DBG_NULL;
		return KNOT_EINVAL;
	}

	if (host_init(params) != KNOT_EOK) {
		return KNOT_ERROR;
	}

	query_t  *conf = params->config;
	uint16_t rclass, rtype;
	uint32_t serial;

	// Command line options processing.
	while ((opt = getopt(argc, argv, "46aCdlrsTvwc:R:t:W:")) != -1) {
		switch (opt) {
		case '4':
			conf->ip = IP_4;
			break;
		case '6':
			conf->ip = IP_6;
			break;
		case 'a':
			conf->type_num = KNOT_RRTYPE_ANY;
			conf->style.format = FORMAT_VERBOSE;
			break;
		case 'C':
			conf->type_num = KNOT_RRTYPE_SOA;
			conf->operation = OPERATION_LIST_SOA;
			break;
		case 'd':
			msg_enable_debug(1);
			break;
		case 'v':
			conf->style.format = FORMAT_VERBOSE;
			break;
		case 'l':
			conf->type_num = KNOT_RRTYPE_AXFR;
			break;
		case 'r':
			conf->flags.rd_flag = false;
			break;
		case 's':
			conf->servfail_stop = true;
			break;
		case 'T':
			conf->protocol = PROTO_TCP;
			break;
		case 'w':
			conf->wait = -1;
			break;
		case 'c':
			if (params_parse_class(optarg, &rclass)
			    != KNOT_EOK) {
				ERR("bad class %s\n", optarg);
				return KNOT_EINVAL;
			}
			conf->class_num = rclass;
			break;
		case 'R':
			if (params_parse_num(optarg, &conf->retries)
			    != KNOT_EOK) {
				return KNOT_EINVAL;
			}
			break;
		case 't':
			if (params_parse_type(optarg, &rtype, &serial)
			    != KNOT_EOK) {
				ERR("bad type %s\n", optarg);
				return KNOT_EINVAL;
			}
			conf->type_num = rtype;
			conf->xfr_serial = serial;
			break;
		case 'W':
			if (params_parse_wait(optarg, &conf->wait)
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
		if (params_parse_server(argv[optind + 1], &conf->servers,
		                        conf->port)
		    != KNOT_EOK) {
			return KNOT_EINVAL;
		}
	case 1: // Fall through.
		if (parse_name(argv[optind], &params->queries, conf)
		    != KNOT_EOK) {
			return KNOT_EINVAL;
		}
		break;
	default:
		host_help(argc, argv);
		return KNOT_ENOTSUP;
	}

	// Complete missing data in queries based on defaults.
	complete_queries(&params->queries, params->config);

	return KNOT_EOK;
}

