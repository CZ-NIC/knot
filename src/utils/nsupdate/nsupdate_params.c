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

#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdarg.h>

#include "utils/nsupdate/nsupdate_params.h"
#include "utils/common/msg.h"
#include "utils/common/netio.h"
#include "common/errcode.h"
#include "common/descriptor_new.h"
#include "libknot/libknot.h"

#define DEFAULT_RETRIES_NSUPDATE	3
#define DEFAULT_TIMEOUT_NSUPDATE	1

static const style_t DEFAULT_STYLE = {
	.format = FORMAT_NSUPDATE,
	.style = { .wrap = false, .show_class = true, .show_ttl = true,
	           .verbose = false, .reduce = false },
	.show_header = true,
	.show_footer = false,
	.show_query = false,
	.show_question = true,
	.show_answer = true,
	.show_authority = true,
	.show_additional = true,
};

static void parse_rr(const scanner_t *s) {
	return; /* Dummy */
}

static void parse_err(const scanner_t *s) {
	ERR("failed to parse RR, %s\n", knot_strerror(s->error_code));
}

static int parser_set_default(scanner_t *s, const char *fmt, ...)
{
	/* Format string. */
	char buf[512]; /* Must suffice for domain name and TTL. */
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (n < 0 || n >= sizeof(buf)) {
		return KNOT_ESPACE;
	}

	/* fmt must contain newline */
	if (scanner_process(buf, buf + n, 0, s) < 0) {
		return KNOT_EPARSEFAIL;
	}

	return KNOT_EOK;
}

static int nsupdate_init(nsupdate_params_t *params)
{
	memset(params, 0, sizeof(*params));

	/* Initialize list. */
	init_list(&params->qfiles);

	/* Default server. */
	params->server = server_create(DEFAULT_IPV4_NAME, DEFAULT_DNS_PORT);
	if (!params->server) return KNOT_ENOMEM;

	/* Default settings. */
	params->ip = IP_ALL;
	params->protocol = PROTO_ALL;
	params->retries = DEFAULT_RETRIES_NSUPDATE;
	params->wait = DEFAULT_TIMEOUT_NSUPDATE;
	params->class_num = KNOT_CLASS_IN;
	params->type_num = KNOT_RRTYPE_SOA;

	/* Default style. */
	params->style = DEFAULT_STYLE;

	/* Initialize RR parser. */
	params->rrp = scanner_create(".");
	if (!params->rrp) return KNOT_ENOMEM;
	params->rrp->process_record = parse_rr;
	params->rrp->process_error = parse_err;
	params->rrp->default_class = params->class_num;
	nsupdate_set_ttl(params, 0);
	nsupdate_set_origin(params, ".");

	return KNOT_EOK;
}

void nsupdate_clean(nsupdate_params_t *params)
{
	strnode_t *n = NULL, *nxt = NULL;

	if (params == NULL) {
		return;
	}

	server_free(params->server);
	server_free(params->srcif);
	free(params->zone);
	scanner_free(params->rrp);
	knot_packet_free(&params->pkt);
	knot_packet_free(&params->resp);

	/* Free qfiles. */
	WALK_LIST_DELSAFE(n, nxt, params->qfiles) {
		free(n);
	}

	/* Free TSIG key. */
	knot_dname_free(&params->key.name);
	free(params->key.secret);

	/* Clean up the structure. */
	memset(params, 0, sizeof(*params));
}

static void nsupdate_help(int argc, char *argv[])
{
	printf("Usage: %s [-d] [-v] [-y [hmac:]name:key] [-p port] "
	       "[-t timeout] [-r retries] [filename]\n",
	       argv[0]);
}

int nsupdate_parse(nsupdate_params_t *params, int argc, char *argv[])
{
	int opt = 0;
	int ret = KNOT_EOK;

	if (params == NULL || argv == NULL) {
		return KNOT_EINVAL;
	}

	ret = nsupdate_init(params);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Command line options processing. */
	while ((opt = getopt(argc, argv, "dDvp:t:r:y:k:")) != -1) {
		switch (opt) {
		case 'd':
		case 'D': /* Extra debugging. */
			msg_enable_debug(1);
			break;
		case 'v':
			params->protocol = PROTO_TCP;
			break;
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
			if (ret != KNOT_EOK) return ret;
			break;
		case 't':
			ret = params_parse_wait(optarg, &params->wait);
			if (ret != KNOT_EOK) return ret;
			break;
		case 'y':
			ret = params_parse_tsig(optarg, &params->key);
			if (ret != KNOT_EOK) return ret;
			break;
		case 'k':
			ret = params_parse_keyfile(optarg, &params->key);
			if (ret != KNOT_EOK) return ret;
			break;
		default:
			nsupdate_help(argc, argv);
			return KNOT_ENOTSUP;
		}
	}

	/* Process non-option parameters. */
	for (; optind < argc; ++optind) {
		strnode_t *n = malloc(sizeof(strnode_t));
		if (!n) { /* Params will be cleaned on exit. */
			return KNOT_ENOMEM;
		}
		n->str = argv[optind];
		add_tail(&params->qfiles, &n->n);
	}

	return ret;
}

int nsupdate_set_ttl(nsupdate_params_t *params, const uint32_t ttl)
{
	int ret = parser_set_default(params->rrp, "$TTL %u\n", ttl);
	if (ret == KNOT_EOK) {
		params->ttl = ttl;
	} else {
		ERR("failed to set default TTL, %s\n", knot_strerror(ret));
	}
	return ret;
}

int nsupdate_set_origin(nsupdate_params_t *params, const char *origin)
{
	char *fqdn = get_fqd_name(origin);

	int ret = parser_set_default(params->rrp, "$ORIGIN %s\n", fqdn);

	free(fqdn);

	if (ret == KNOT_EOK) {
		if (params->zone) free(params->zone);
		params->zone = strdup(origin);
	} else {
		ERR("failed to set default origin, %s\n", knot_strerror(ret));
	}
	return ret;
}

