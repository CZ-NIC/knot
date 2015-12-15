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

#include <assert.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils/knsupdate/knsupdate_params.h"
#include "utils/common/msg.h"
#include "utils/common/netio.h"
#include "libknot/libknot.h"
#include "libknot/tsig.h"
#include "contrib/mempattern.h"
#include "contrib/ucw/mempool.h"

#define DEFAULT_RETRIES_NSUPDATE	3
#define DEFAULT_TIMEOUT_NSUPDATE	12

static const style_t DEFAULT_STYLE_NSUPDATE = {
	.format = FORMAT_NSUPDATE,
	.style = {
		.wrap = false,
		.show_class = true,
		.show_ttl = true,
		.verbose = false,
		.empty_ttl = false,
		.human_ttl = false,
		.human_tmstamp = true,
		.generic = false,
		.ascii_to_idn = NULL
	},
	.show_query = false,
	.show_header = true,
	.show_edns = false,
	.show_question = true,
	.show_answer = true,
	.show_authority = true,
	.show_additional = true,
	.show_tsig = true,
	.show_footer = false
};

static void parse_err(zs_scanner_t *s) {
	ERR("failed to parse RR: %s\n", zs_strerror(s->error_code));
}

static int parser_set_default(zs_scanner_t *s, const char *fmt, ...)
{
	/* Format string. */
	char buf[512]; /* Must suffice for domain name and TTL. */
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (n < 0 || (size_t)n >= sizeof(buf)) {
		return KNOT_ESPACE;
	}

	/* Buffer must contain newline */
	if (zs_scanner_parse(s, buf, buf + n, true) < 0) {
		return KNOT_EPARSEFAIL;
	}

	return KNOT_EOK;
}

static int knsupdate_init(knsupdate_params_t *params)
{
	memset(params, 0, sizeof(knsupdate_params_t));

	/* Initialize lists. */
	init_list(&params->qfiles);
	init_list(&params->update_list);
	init_list(&params->prereq_list);

	/* Initialize memory context. */
	mm_ctx_mempool(&params->mm, MM_DEFAULT_BLKSIZE);

	/* Default server. */
	params->server = srv_info_create(DEFAULT_IPV4_NAME, DEFAULT_DNS_PORT);
	if (!params->server)
		return KNOT_ENOMEM;

	/* Default settings. */
	params->ip = IP_ALL;
	params->protocol = PROTO_ALL;
	params->class_num = KNOT_CLASS_IN;
	params->type_num = KNOT_RRTYPE_SOA;
	params->ttl = 0;
	params->retries = DEFAULT_RETRIES_NSUPDATE;
	params->wait = DEFAULT_TIMEOUT_NSUPDATE;
	params->zone = strdup(".");

	/* Initialize RR parser. */
	params->parser = zs_scanner_create(".", params->class_num, 0,
	                                   NULL, parse_err, NULL);
	if (!params->parser)
		return KNOT_ENOMEM;

	/* Default style. */
	params->style = DEFAULT_STYLE_NSUPDATE;

	/* Create query/answer packets. */
	params->query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, &params->mm);
	params->answer = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, &params->mm);

	return KNOT_EOK;
}

void knsupdate_clean(knsupdate_params_t *params)
{
	if (params == NULL) {
		return;
	}

	/* Clear current query. */
	knsupdate_reset(params);

	/* Free qfiles. */
	ptrlist_free(&params->qfiles, &params->mm);

	srv_info_free(params->server);
	srv_info_free(params->srcif);
	free(params->zone);
	zs_scanner_free(params->parser);
	knot_pkt_free(&params->query);
	knot_pkt_free(&params->answer);
	knot_tsig_key_deinit(&params->tsig_key);

	/* Clean up the structure. */
	mp_delete(params->mm.ctx);
	memset(params, 0, sizeof(*params));
}

/*! \brief Free RRSet list. */
static void rr_list_free(list_t *list, knot_mm_t *mm)
{
	assert(list != NULL);
	assert(mm != NULL);

	ptrnode_t *node = NULL;
	WALK_LIST(node, *list) {
		knot_rrset_t *rrset = (knot_rrset_t *)node->d;
		knot_rrset_free(&rrset, NULL);
	}
	ptrlist_free(list, mm);
}

void knsupdate_reset(knsupdate_params_t *params)
{
	/* Free ADD/REMOVE RRSets. */
	rr_list_free(&params->update_list, &params->mm);

	/* Free PREREQ RRSets. */
	rr_list_free(&params->prereq_list, &params->mm);
}

static void knsupdate_help(void)
{
	printf("Usage: knsupdate [-d] [-v] [-k keyfile | -y [hmac:]name:key]\n"
	       "                 [-p port] [-t timeout] [-r retries] [filename]\n");
}

int knsupdate_parse(knsupdate_params_t *params, int argc, char *argv[])
{
	int opt = 0, li = 0;
	int ret = KNOT_EOK;

	if (params == NULL || argv == NULL) {
		return KNOT_EINVAL;
	}

	ret = knsupdate_init(params);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Long options.
	struct option opts[] = {
		{ "version", no_argument, 0, 'V' },
		{ "help",    no_argument, 0, 'h' },
		{ 0,         0,           0, 0 }
	};

	/* Command line options processing. */
	while ((opt = getopt_long(argc, argv, "dhDvVp:t:r:y:k:", opts, &li))
	       != -1) {
		switch (opt) {
		case 'd':
		case 'D': /* Extra debugging. */
			msg_enable_debug(1);
			break;
		case 'h':
			knsupdate_help();
			params->stop = true;
			return KNOT_EOK;
		case 'v':
			params->protocol = PROTO_TCP;
			break;
		case 'V':
			printf(KNSUPDATE_VERSION);
			params->stop = true;
			return KNOT_EOK;
		case 'p':
			free(params->server->service);
			params->server->service = strdup(optarg);
			if (!params->server->service) {
				ERR("failed to set default port '%s'\n", optarg);
				return KNOT_ENOMEM;
			}
			break;
		case 'r':
			ret = params_parse_num(optarg, &params->retries);
			if (ret != KNOT_EOK) {
				return ret;
			}
			break;
		case 't':
			ret = params_parse_wait(optarg, &params->wait);
			if (ret != KNOT_EOK) {
				return ret;
			}
			break;
		case 'y':
			knot_tsig_key_deinit(&params->tsig_key);
			ret = knot_tsig_key_init_str(&params->tsig_key, optarg);
			if (ret != KNOT_EOK) {
				ERR("failed to parse key '%s'\n", optarg);
				return ret;
			}
			break;
		case 'k':
			knot_tsig_key_deinit(&params->tsig_key);
			ret = knot_tsig_key_init_file(&params->tsig_key, optarg);
			if (ret != KNOT_EOK) {
				ERR("failed to parse keyfile '%s'\n", optarg);
				return ret;
			}
			break;
		default:
			knsupdate_help();
			return KNOT_ENOTSUP;
		}
	}

	/* No retries for TCP. */
	if (params->protocol == PROTO_TCP) {
		params->retries = 0;
	} else {
		/* If wait/tries < 1 s, set 1 second for each try. */
		if (params->wait > 0 &&
		    (uint32_t)params->wait < ( 1 + params->retries)) {
			params->wait = 1;
		} else {
			params->wait /= (1 + params->retries);
		}
	}

	/* Process non-option parameters. */
	for (; optind < argc; ++optind) {
		ptrlist_add(&params->qfiles, argv[optind], &params->mm);
	}

	return ret;
}

int knsupdate_set_ttl(knsupdate_params_t *params, const uint32_t ttl)
{
	int ret = parser_set_default(params->parser, "$TTL %u\n", ttl);
	if (ret == KNOT_EOK) {
		params->ttl = ttl;
	} else {
		ERR("failed to set default TTL, %s\n", knot_strerror(ret));
	}
	return ret;
}

int knsupdate_set_origin(knsupdate_params_t *params, const char *origin)
{
	char *fqdn = get_fqd_name(origin);

	int ret = parser_set_default(params->parser, "$ORIGIN %s\n", fqdn);

	free(fqdn);

	if (ret != KNOT_EOK) {
		ERR("failed to set default origin, %s\n", knot_strerror(ret));
	}
	return ret;
}
