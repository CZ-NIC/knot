/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <getopt.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils/khost/khost_params.h"
#include "utils/kdig/kdig_params.h"
#include "utils/common/msg.h"
#include "utils/common/params.h"
#include "utils/common/resolv.h"
#include "libknot/libknot.h"
#include "contrib/strtonum.h"
#include "contrib/ucw/lists.h"

#define PROGRAM_NAME "khost"

#define DEFAULT_RETRIES_HOST	1
#define DEFAULT_TIMEOUT_HOST	2

static const style_t DEFAULT_STYLE_HOST = {
	.format = FORMAT_HOST,
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
	.show_header = false,
	.show_edns = false,
	.show_question = true,
	.show_answer = true,
	.show_authority = true,
	.show_additional = true,
	.show_tsig = false,
	.show_footer = false
};

static int khost_init(kdig_params_t *params)
{
	// Initialize params with kdig defaults.
	int ret = kdig_init(params);

	if (ret != KNOT_EOK) {
		return ret;
	}

	// Set khost specific defaults.
	free(params->config->port);
	params->config->port = strdup(DEFAULT_DNS_PORT);
	params->config->retries = DEFAULT_RETRIES_HOST;
	params->config->wait = DEFAULT_TIMEOUT_HOST;
	params->config->class_num = KNOT_CLASS_IN;
	params->config->style = DEFAULT_STYLE_HOST;
	params->config->idn = true;

	// Check port.
	if (params->config->port == NULL) {
		query_free(params->config);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

void khost_clean(kdig_params_t *params)
{
	if (params == NULL) {
		DBG_NULL;
		return;
	}

	kdig_clean(params);
}

static int parse_server(const char *value, list_t *servers, const char *def_port)
{
	if (params_parse_server(value, servers, def_port) != KNOT_EOK) {
		ERR("invalid server '%s'\n", value);
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int parse_name(const char *value, list_t *queries, const query_t *conf)
{
	char	*reverse = get_reverse_name(value);
	char	*ascii_name = (char *)value;
	query_t	*query;

	if (conf->idn) {
		ascii_name = name_from_idn(value);
		if (ascii_name == NULL) {
			free(reverse);
			return KNOT_EINVAL;
		}
	}

	// If name is not FQDN, append trailing dot.
	char *fqd_name = get_fqd_name(ascii_name);

	if (conf->idn) {
		free(ascii_name);
	}

	// RR type is known.
	if (conf->type_num >= 0) {
		if (conf->type_num == KNOT_RRTYPE_PTR) {
			free(fqd_name);

			// Check for correct address.
			if (reverse == NULL) {
				ERR("invalid IPv4/IPv6 address '%s'\n", value);
				return KNOT_EINVAL;
			}

			// Add reverse query for address.
			query = query_create(reverse, conf);
			free(reverse);
			if (query == NULL) {
				return KNOT_ENOMEM;
			}
			add_tail(queries, (node_t *)query);
		} else {
			free(reverse);

			// Add query for name and specified type.
			query = query_create(fqd_name, conf);
			free(fqd_name);
			if (query == NULL) {
				return KNOT_ENOMEM;
			}
			add_tail(queries, (node_t *)query);
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
			add_tail(queries, (node_t *)query);

			// Add query for name and type AAAA.
			query = query_create(fqd_name, conf);
			if (query == NULL) {
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			query->type_num = KNOT_RRTYPE_AAAA;
			query->style.hide_cname = true;
			add_tail(queries, (node_t *)query);

			// Add query for name and type MX.
			query = query_create(fqd_name, conf);
			if (query == NULL) {
				free(fqd_name);
				return KNOT_ENOMEM;
			}
			free(fqd_name);
			query->type_num = KNOT_RRTYPE_MX;
			query->style.hide_cname = true;
			add_tail(queries, (node_t *)query);
		} else {
			free(fqd_name);

			// Add reverse query for address.
			query = query_create(reverse, conf);
			free(reverse);
			if (query == NULL) {
				return KNOT_ENOMEM;
			}
			query->type_num = KNOT_RRTYPE_PTR;
			add_tail(queries, (node_t *)query);
		}
	}

	return KNOT_EOK;
}

static void print_help(void)
{
	printf("Usage: %s [-4] [-6] [-adhrsTvVw] [-c class] [-t type]\n"
	       "             [-R retries] [-W time] name [server]\n\n"
	       "       -4             Use IPv4 protocol only.\n"
	       "       -6             Use IPv6 procotol only.\n"
	       "       -a             Same as -t ANY -v.\n"
	       "       -d             Allow debug messages.\n"
	       "       -h, --help     Print the program help.\n"
	       "       -r             Disable recursion.\n"
	       "       -T             Use TCP procotol.\n"
	       "       -v             Verbose output.\n"
	       "       -V, --version  Print the program version.\n"
	       "       -w             Wait forever.\n"
	       "       -c             Set query class.\n"
	       "       -t             Set query type.\n"
	       "       -R             Set number of UDP retries.\n"
	       "       -W             Set wait interval.\n",
	       PROGRAM_NAME);
}

int khost_parse(kdig_params_t *params, int argc, char *argv[])
{
	if (params == NULL || argv == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	if (khost_init(params) != KNOT_EOK) {
		return KNOT_ERROR;
	}

#ifdef LIBIDN
	// Set up localization.
	if (setlocale(LC_CTYPE, "") == NULL) {
		params->config->idn = false;
	}
#endif

	query_t  *conf = params->config;
	uint16_t rclass, rtype;
	int64_t  serial;
	bool     notify;

	// Long options.
	struct option opts[] = {
		{ "help",    no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{ NULL }
	};

	// Command line options processing.
	int opt = 0;
	while ((opt = getopt_long(argc, argv, "46adhrsTvVwc:t:R:W:", opts, NULL))
	       != -1) {
		switch (opt) {
		case '4':
			conf->ip = IP_4;
			break;
		case '6':
			conf->ip = IP_6;
			break;
		case 'a':
			conf->type_num = KNOT_RRTYPE_ANY;
			conf->style.format = FORMAT_FULL;
			conf->style.show_header = true;
			conf->style.show_edns = true;
			conf->style.show_footer = true;
			break;
		case 'd':
			msg_enable_debug(1);
			break;
		case 'h':
			print_help();
			params->stop = false;
			return KNOT_EOK;
		case 'r':
			conf->flags.rd_flag = false;
			break;
		case 'T':
			conf->protocol = PROTO_TCP;
			break;
		case 'v':
			conf->style.format = FORMAT_FULL;
			conf->style.show_header = true;
			conf->style.show_edns = true;
			conf->style.show_footer = true;
			break;
		case 'V':
			print_version(PROGRAM_NAME);
			params->stop = false;
			return KNOT_EOK;
		case 'w':
			conf->wait = -1;
			break;
		case 'c':
			if (params_parse_class(optarg, &rclass) != KNOT_EOK) {
				ERR("invalid class '%s'\n", optarg);
				return KNOT_EINVAL;
			}
			conf->class_num = rclass;
			break;
		case 't':
			if (params_parse_type(optarg, &rtype, &serial, &notify)
			    != KNOT_EOK) {
				ERR("invalid type '%s'\n", optarg);
				return KNOT_EINVAL;
			}
			conf->type_num = rtype;
			conf->serial = serial;
			conf->notify = notify;

			// If NOTIFY, reset default RD flag.
			if (conf->notify) {
				conf->flags.rd_flag = false;
			}
			break;
		case 'R':
			if (str_to_u32(optarg, &conf->retries) != KNOT_EOK) {
				ERR("invalid retries '%s'\n", optarg);
				return KNOT_EINVAL;
			}
			break;
		case 'W':
			if (params_parse_wait(optarg, &conf->wait) != KNOT_EOK) {
				ERR("invalid wait '%s'\n", optarg);
				return KNOT_EINVAL;
			}
			break;
		default:
			print_help();
			return KNOT_ENOTSUP;
		}
	}

	// Process non-option parameters.
	switch (argc - optind) {
	case 2:
		if (parse_server(argv[optind + 1], &conf->servers, conf->port)
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
		print_help();
		return KNOT_ENOTSUP;
	}

	// Complete missing data in queries based on defaults.
	complete_queries(&params->queries, params->config);

	return KNOT_EOK;
}
