/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
#include "contrib/base64.h"
#include "contrib/mempattern.h"
#include "contrib/strtonum.h"
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
		.original_ttl = false,
		.empty_ttl = false,
		.human_ttl = false,
		.human_timestamp = true,
		.generic = false,
		.ascii_to_idn = NULL
	},
	.show_query = false,
	.show_header = true,
	.show_section = true,
	.show_edns = false,
	.show_question = true,
	.show_answer = true,
	.show_authority = true,
	.show_additional = true,
	.show_tsig = true,
	.show_footer = false
};

static int parser_set_default(zs_scanner_t *s, const char *fmt, ...)
{
	/* Format string. */
	char buf[512]; /* Must suffice for domain name and TTL. */
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (n < 0 || (size_t)n >= sizeof(buf)) {
		return ZS_EINVAL;
	}

	/* Buffer must contain newline */
	if (zs_set_input_string(s, buf, n) != 0 ||
	    zs_parse_all(s) != 0) {
		return s->error.code;
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

	tls_params_init(&params->tls_params);

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
	params->retries = DEFAULT_RETRIES_NSUPDATE;
	params->wait = DEFAULT_TIMEOUT_NSUPDATE;

	/* Initialize RR parser. */
	if (zs_init(&params->parser, ".", params->class_num, 3600) != 0 ||
	    zs_set_processing(&params->parser, NULL, NULL, NULL) != 0) {
		zs_deinit(&params->parser);
		return KNOT_ENOMEM;
	}

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
	zs_deinit(&params->parser);
	knot_pkt_free(params->query);
	knot_pkt_free(params->answer);
	knot_tsig_key_deinit(&params->tsig_key);

	tls_params_clean(&params->tls_params);
	quic_params_clean(&params->quic_params);

	/* Clean up the structure. */
	mp_delete(params->mm.ctx);
	memset(params, 0, sizeof(*params));
}

/*! \brief Free RRSet list. */
static void rr_list_free(list_t *list, knot_mm_t *mm)
{
	assert(list != NULL);
	assert(mm != NULL);

	ptrnode_t *node;
	WALK_LIST(node, *list) {
		knot_rrset_t *rrset = (knot_rrset_t *)node->d;
		knot_rrset_free(rrset, NULL);
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

static void print_help(void)
{
	printf("Usage:\n"
	       " %s [-T] [options] [filename]\n"
	       " %s [-S | -Q] [tls_options] [options] [filename]\n"
	       "\n"
	       "Options:\n"
	       "  -T, --tcp              Use TCP protocol.\n"
	       "  -S, --tls              Use TLS protocol.\n"
	       "  -Q, --quic             Use QUIC protocol.\n"
	       "  -p, --port <num>       Remote port.\n"
	       "  -r, --retry <num>      Number of retries over UDP.\n"
	       "  -t, --timeout <num>    Update timeout.\n"
	       "  -y, --tsig <str>       TSIG key in the form [alg:]name:key.\n"
	       "  -k, --tsigfile <path>  Path to a TSIG key file.\n"
	       "  -d, --debug            Debug mode output.\n"
	       "  -h, --help             Print the program help.\n"
	       "  -V, --version          Print the program version.\n"
	       "\n"
	       "QUIC/TLS options:\n"
	       "  -H, --hostname <str>   Remote hostname validation.\n"
	       "  -P, --pin <base64>     Certificate key PIN.\n"
	       "  -A, --ca [<path>]      Path to a CA file.\n"
	       "  -E, --certfile <path>  Path to a client certificate file.\n"
	       "  -K, --keyfile <path>   Path to a client key file.\n"
	       "  -s, --sni <str>        Remote SNI.\n",
	       PROGRAM_NAME, PROGRAM_NAME);
}

int knsupdate_parse(knsupdate_params_t *params, int argc, char *argv[])
{
	if (params == NULL || argv == NULL) {
		return KNOT_EINVAL;
	}

	int ret = knsupdate_init(params);
	if (ret != KNOT_EOK) {
		return ret;
	}

	const char *opts_str = "dhvTSQV::p:r:t:y:k:H:P:A::E:K:s:";
	struct option opts[] = {
		{ "debug",    no_argument,       NULL, 'd' },
		{ "help",     no_argument,       NULL, 'h' },
		{ "tcp",      no_argument,       NULL, 'T' },
		{ "tls",      no_argument,       NULL, 'S' },
		{ "quic",     no_argument,       NULL, 'Q' },
		{ "version",  optional_argument, NULL, 'V' },
		{ "port",     required_argument, NULL, 'p' },
		{ "retry",    required_argument, NULL, 'r' },
		{ "timeout",  required_argument, NULL, 't' },
		{ "tsig",     required_argument, NULL, 'y' },
		{ "tsigfile", required_argument, NULL, 'k' },
		{ "hostname", required_argument, NULL, 'H' },
		{ "pin",      required_argument, NULL, 'P' },
		{ "ca",       optional_argument, NULL, 'A' },
		{ "certfile", required_argument, NULL, 'E' },
		{ "keyfile",  required_argument, NULL, 'K' },
		{ "sni",      required_argument, NULL, 's' },
		{ NULL }
	};

	bool default_port = true;

	int opt = 0;
	while ((opt = getopt_long(argc, argv, opts_str, opts, NULL)) != -1) {
		switch (opt) {
		case 'd':
			msg_enable_debug(1);
			break;
		case 'h':
			print_help();
			params->stop = true;
			return KNOT_EOK;
		case 'v': // Compatibility with nsupdate.
		case 'T':
			params->protocol = PROTO_TCP;
			break;
		case 'S':
			params->protocol = PROTO_TCP;

			params->tls_params.enable = true;

			if (default_port) {
				free(params->server->service);
				params->server->service = strdup(DEFAULT_DNS_TLS_PORT);
			}
			break;
		case 'Q':
			params->protocol = PROTO_UDP;

			params->tls_params.enable = true;
			params->quic_params.enable = true;

			if (default_port) {
				free(params->server->service);
				params->server->service = strdup(DEFAULT_DNS_QUIC_PORT);
			}
			break;
		case 'V':
			print_version(PROGRAM_NAME, optarg != NULL);
			params->stop = true;
			return KNOT_EOK;
		case 'p':
			assert(optarg);
			default_port = false;
			free(params->server->service);
			params->server->service = strdup(optarg);
			break;
		case 'r':
			ret = str_to_u32(optarg, &params->retries);
			if (ret != KNOT_EOK) {
				ERR("invalid retries '%s'", optarg);
				return ret;
			}
			break;
		case 't':
			ret = params_parse_wait(optarg, &params->wait);
			if (ret != KNOT_EOK) {
				ERR("invalid timeout '%s'", optarg);
				return ret;
			}
			break;
		case 'y':
			knot_tsig_key_deinit(&params->tsig_key);
			ret = knot_tsig_key_init_str(&params->tsig_key, optarg);
			if (ret != KNOT_EOK) {
				ERR("failed to parse TSIG key '%s'", optarg);
				return ret;
			}
			break;
		case 'k':
			knot_tsig_key_deinit(&params->tsig_key);
			ret = knot_tsig_key_init_file(&params->tsig_key, optarg);
			if (ret != KNOT_EOK) {
				ERR("failed to parse TSIG keyfile '%s'", optarg);
				return ret;
			}
			break;
		case 'H':
			assert(optarg);
			free(params->tls_params.hostname);
			params->tls_params.hostname = strdup(optarg);
			break;
		case 'P':
			assert(optarg);
			uint8_t pin[64] = { 0 };
			ret = knot_base64_decode((const uint8_t *)optarg, strlen(optarg), pin, sizeof(pin));
			if (ret < 0) {
				ERR("invalid certificate pin %s", optarg);
				return ret;
			} else if (ret != CERT_PIN_LEN) { // Check for 256-bit value.
				ERR("invalid SHA256 hash length of certificate pin %s", optarg);
				return KNOT_EINVAL;
			}

			uint8_t *item = malloc(1 + ret); // 1 ~ leading data length.
			if (item == NULL) {
				return KNOT_ENOMEM;
			}
			item[0] = ret;
			memcpy(&item[1], pin, ret);

			if (ptrlist_add(&params->tls_params.pins, item, NULL) == NULL) {
				return KNOT_ENOMEM;
			}

			break;
		case 'A':
			if (optarg == NULL) {
				params->tls_params.system_ca = true;
				break;
			}
			if (ptrlist_add(&params->tls_params.ca_files, strdup(optarg), NULL) == NULL) {
				ERR("failed to set CA file '%s'", optarg);
				return KNOT_ENOMEM;
			}
			break;
		case 'E':
			assert(optarg);
			free(params->tls_params.certfile);
			params->tls_params.certfile = strdup(optarg);
			break;
		case 'K':
			assert(optarg);
			free(params->tls_params.keyfile);
			params->tls_params.keyfile = strdup(optarg);
			break;
		case 's':
			assert(optarg);
			free(params->tls_params.sni);
			params->tls_params.sni = strdup(optarg);
			break;
		default:
			print_help();
			return KNOT_ENOTSUP;
		}
	}

	/* Retries only for UDP. */
	if (params->protocol == PROTO_TCP || params->quic_params.enable) {
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

	return KNOT_EOK;
}

int knsupdate_set_ttl(knsupdate_params_t *params, const uint32_t ttl)
{
	int ret = parser_set_default(&params->parser, "$TTL %u\n", ttl);
	if (ret != KNOT_EOK) {
		ERR("failed to set default TTL, %s", zs_strerror(ret));
	}
	return ret;
}

int knsupdate_set_origin(knsupdate_params_t *params, const char *origin)
{
	char *fqdn = get_fqd_name(origin);

	int ret = parser_set_default(&params->parser, "$ORIGIN %s\n", fqdn);

	free(fqdn);

	if (ret != KNOT_EOK) {
		ERR("failed to set default origin, %s", zs_strerror(ret));
	}
	return ret;
}
