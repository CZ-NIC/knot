/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <arpa/inet.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils/kdig/kdig_params.h"
#include "utils/common/cert.h"
#include "utils/common/hex.h"
#include "utils/common/msg.h"
#include "utils/common/netio.h"
#include "utils/common/params.h"
#include "utils/common/resolv.h"
#include "libknot/descriptor.h"
#include "libknot/libknot.h"
#include "contrib/base64.h"
#include "contrib/sockaddr.h"
#include "contrib/string.h"
#include "contrib/strtonum.h"
#include "contrib/ucw/lists.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"

#define PROGRAM_NAME "kdig"

#define DEFAULT_RETRIES_DIG		2
#define DEFAULT_TIMEOUT_DIG		5
#define DEFAULT_ALIGNMENT_SIZE		128
#define DEFAULT_TLS_OCSP_STAPLING	(7 * 24 * 3600)

#define BADCOOKIE_RETRY_MAX		10

static const flags_t DEFAULT_FLAGS_DIG = {
	.aa_flag = false,
	.tc_flag = false,
	.rd_flag = true,
	.ra_flag = false,
	.z_flag  = false,
	.ad_flag = false,
	.cd_flag = false,
	.do_flag = false
};

static const style_t DEFAULT_STYLE_DIG = {
	.format = FORMAT_FULL,
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
		.ascii_to_idn = name_to_idn
	},
	.show_query = false,
	.show_header = true,
	.show_section = true,
	.show_edns = true,
	.show_question = true,
	.show_answer = true,
	.show_authority = true,
	.show_additional = true,
	.show_tsig = true,
	.show_footer = true
};

static int opt_multiline(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.wrap = true;
	q->style.format = FORMAT_FULL;
	q->style.show_header = true;
	q->style.show_edns = true;
	q->style.show_footer = true;
	q->style.style.verbose = true;

	return KNOT_EOK;
}

static int opt_nomultiline(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.wrap = false;

	return KNOT_EOK;
}

static int opt_short(const char *arg, void *query)
{
	query_t *q = query;

	q->style.format = FORMAT_DIG;
	q->style.show_header = false;
	q->style.show_edns = false;
	q->style.show_footer = false;

	return KNOT_EOK;
}

static int opt_noshort(const char *arg, void *query)
{
	query_t *q = query;

	q->style.format = FORMAT_FULL;

	return KNOT_EOK;
}

static int opt_generic(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.generic = true;

	return KNOT_EOK;
}

static int opt_nogeneric(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.generic = false;

	return KNOT_EOK;
}

static int opt_aaflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.aa_flag = true;

	return KNOT_EOK;
}

static int opt_noaaflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.aa_flag = false;

	return KNOT_EOK;
}

static int opt_tcflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.tc_flag = true;

	return KNOT_EOK;
}

static int opt_notcflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.tc_flag = false;

	return KNOT_EOK;
}

static int opt_rdflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.rd_flag = true;

	return KNOT_EOK;
}

static int opt_nordflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.rd_flag = false;

	return KNOT_EOK;
}

static int opt_raflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.ra_flag = true;

	return KNOT_EOK;
}

static int opt_noraflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.ra_flag = false;

	return KNOT_EOK;
}

static int opt_zflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.z_flag = true;

	return KNOT_EOK;
}

static int opt_nozflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.z_flag = false;

	return KNOT_EOK;
}

static int opt_adflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.ad_flag = true;

	return KNOT_EOK;
}

static int opt_noadflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.ad_flag = false;

	return KNOT_EOK;
}

static int opt_cdflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.cd_flag = true;

	return KNOT_EOK;
}

static int opt_nocdflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.cd_flag = false;

	return KNOT_EOK;
}

static int opt_doflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.do_flag = true;

	return KNOT_EOK;
}

static int opt_nodoflag(const char *arg, void *query)
{
	query_t *q = query;

	q->flags.do_flag = false;

	return KNOT_EOK;
}

static int opt_all(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_header = true;
	q->style.show_section = true;
	q->style.show_edns = true;
	q->style.show_question = true;
	q->style.show_answer = true;
	q->style.show_authority = true;
	q->style.show_additional = true;
	q->style.show_tsig = true;
	q->style.show_footer = true;

	return KNOT_EOK;
}

static int opt_noall(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_header = false;
	q->style.show_section = false;
	q->style.show_edns = false;
	q->style.show_query = false;
	q->style.show_question = false;
	q->style.show_answer = false;
	q->style.show_authority = false;
	q->style.show_additional = false;
	q->style.show_tsig = false;
	q->style.show_footer = false;

	return KNOT_EOK;
}

static int opt_qr(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_query = true;

	return KNOT_EOK;
}

static int opt_noqr(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_query = false;

	return KNOT_EOK;
}

static int opt_header(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_header = true;

	return KNOT_EOK;
}

static int opt_noheader(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_header = false;

	return KNOT_EOK;
}

static int opt_comments(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_section = true;

	return KNOT_EOK;
}

static int opt_nocomments(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_section = false;

	return KNOT_EOK;
}

static int opt_opt(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_edns = true;

	return KNOT_EOK;
}

static int opt_noopt(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_edns = false;

	return KNOT_EOK;
}

static int opt_opttext(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_edns_opt_text = true;

	return KNOT_EOK;
}

static int opt_noopttext(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_edns_opt_text = false;

	return KNOT_EOK;
}

static int opt_question(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_question = true;

	return KNOT_EOK;
}

static int opt_noquestion(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_question = false;

	return KNOT_EOK;
}

static int opt_answer(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_answer = true;

	return KNOT_EOK;
}

static int opt_noanswer(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_answer = false;

	return KNOT_EOK;
}

static int opt_authority(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_authority = true;

	return KNOT_EOK;
}

static int opt_noauthority(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_authority = false;

	return KNOT_EOK;
}

static int opt_additional(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_additional = true;

	return KNOT_EOK;
}

static int opt_noadditional(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_additional = false;
	q->style.show_edns = false;
	q->style.show_tsig = false;

	return KNOT_EOK;
}

static int opt_tsig(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_tsig = true;

	return KNOT_EOK;
}

static int opt_notsig(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_tsig = false;

	return KNOT_EOK;
}

static int opt_stats(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_footer = true;

	return KNOT_EOK;
}

static int opt_nostats(const char *arg, void *query)
{
	query_t *q = query;

	q->style.show_footer = false;

	return KNOT_EOK;
}

static int opt_class(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.show_class = true;

	return KNOT_EOK;
}

static int opt_noclass(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.show_class = false;

	return KNOT_EOK;
}

static int opt_ttl(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.show_ttl = true;

	return KNOT_EOK;
}

static int opt_nottl(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.show_ttl = false;

	return KNOT_EOK;
}

static int opt_ignore(const char *arg, void *query)
{
	query_t *q = query;

	q->ignore_tc = true;

	return KNOT_EOK;
}

static int opt_noignore(const char *arg, void *query)
{
	query_t *q = query;

	q->ignore_tc = false;

	return KNOT_EOK;
}

static int opt_crypto(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.hide_crypto = false;

	return KNOT_EOK;
}

static int opt_nocrypto(const char *arg, void *query)
{
	query_t *q = query;

	q->style.style.hide_crypto = true;

	return KNOT_EOK;
}

static int opt_tcp(const char *arg, void *query)
{
	query_t *q = query;

	q->protocol = PROTO_TCP;

	return KNOT_EOK;
}

static int opt_notcp(const char *arg, void *query)
{
	query_t *q = query;

	q->protocol = PROTO_UDP;
	return opt_ignore(arg, query);
}

static int opt_fastopen(const char *arg, void *query)
{
	query_t *q = query;

	q->fastopen = true;

	return opt_tcp(arg, query);
}

static int opt_nofastopen(const char *arg, void *query)
{
	query_t *q = query;

	q->fastopen = false;

	return KNOT_EOK;
}

static int opt_keepopen(const char *arg, void *query)
{
	query_t *q = query;

	q->keepopen = true;

	return KNOT_EOK;
}

static int opt_nokeepopen(const char *arg, void *query)
{
	query_t *q = query;

	q->keepopen = false;

	return KNOT_EOK;
}

static int opt_tls(const char *arg, void *query)
{
	query_t *q = query;

	q->tls.enable = true;
	return opt_tcp(arg, query);
}

static int opt_notls(const char *arg, void *query)
{
	query_t *q = query;

	tls_params_clean(&q->tls);
	tls_params_init(&q->tls);

	return KNOT_EOK;
}

static int opt_tls_ca(const char *arg, void *query)
{
	query_t *q = query;

	if (arg == NULL) {
		q->tls.system_ca = true;
		return opt_tls(arg, query);
	} else {
		if (ptrlist_add(&q->tls.ca_files, strdup(arg), NULL) == NULL) {
			return KNOT_ENOMEM;
		}
		return opt_tls(arg, query);
	}
}

static int opt_notls_ca(const char *arg, void *query)
{
	query_t *q = query;

	q->tls.system_ca = false;

	ptrnode_t *node, *nxt;
	WALK_LIST_DELSAFE(node, nxt, q->tls.ca_files) {
		free(node->d);
	}
	ptrlist_free(&q->tls.ca_files, NULL);

	return KNOT_EOK;
}

static int opt_tls_pin(const char *arg, void *query)
{
	query_t *q = query;

	uint8_t pin[64] = { 0 };

	int ret = knot_base64_decode((const uint8_t *)arg, strlen(arg), pin, sizeof(pin));
	if (ret < 0) {
		ERR("invalid +tls-pin=%s\n", arg);
		return ret;
	} else if (ret != CERT_PIN_LEN) { // Check for 256-bit value.
		ERR("invalid sha256 hash length +tls-pin=%s\n", arg);
		return KNOT_EINVAL;
	}

	uint8_t *item = malloc(1 + ret); // 1 ~ leading data length.
	if (item == NULL) {
		return KNOT_ENOMEM;
	}
	item[0] = ret;
	memcpy(&item[1], pin, ret);

	if (ptrlist_add(&q->tls.pins, item, NULL) == NULL) {
		return KNOT_ENOMEM;
	}

	return opt_tls(arg, query);
}

static int opt_notls_pin(const char *arg, void *query)
{
	query_t *q = query;

	ptrnode_t *node, *nxt;
	WALK_LIST_DELSAFE(node, nxt, q->tls.pins) {
		free(node->d);
	}
	ptrlist_free(&q->tls.pins, NULL);

	return KNOT_EOK;
}

static int opt_tls_hostname(const char *arg, void *query)
{
	query_t *q = query;

	free(q->tls.hostname);
	q->tls.hostname = strdup(arg);

	return opt_tls(arg, query);
}

static int opt_notls_hostname(const char *arg, void *query)
{
	query_t *q = query;

	free(q->tls.hostname);
	q->tls.hostname = NULL;

	return KNOT_EOK;
}

static int opt_tls_sni(const char *arg, void *query)
{
	query_t *q = query;

	free(q->tls.sni);
	q->tls.sni = strdup(arg);

	return opt_tls(arg, query);
}

static int opt_notls_sni(const char *arg, void *query)
{
	query_t *q = query;

	free(q->tls.sni);
	q->tls.sni = NULL;

	return KNOT_EOK;
}

static int opt_tls_keyfile(const char *arg, void *query)
{
	query_t *q = query;

	free(q->tls.keyfile);
	q->tls.keyfile = strdup(arg);

	return opt_tls(arg, query);
}

static int opt_notls_keyfile(const char *arg, void *query)
{
	query_t *q = query;

	free(q->tls.keyfile);
	q->tls.keyfile = NULL;

	return KNOT_EOK;
}

static int opt_tls_certfile(const char *arg, void *query)
{
	query_t *q = query;

	free(q->tls.certfile);
	q->tls.certfile = strdup(arg);

	return opt_tls(arg, query);
}

static int opt_notls_certfile(const char *arg, void *query)
{
	query_t *q = query;

	free(q->tls.certfile);
	q->tls.certfile = NULL;

	return KNOT_EOK;
}

static int opt_tls_ocsp_stapling(const char *arg, void *query)
{
	query_t *q = query;

	if (arg == NULL) {
		q->tls.ocsp_stapling = DEFAULT_TLS_OCSP_STAPLING;
		return opt_tls(arg, query);
	} else {
		uint32_t num = 0;
		if (str_to_u32(arg, &num) != KNOT_EOK || num == 0) {
			ERR("invalid +tls-ocsp-stapling=%s\n", arg);
			return KNOT_EINVAL;
		}

		q->tls.ocsp_stapling = 3600 * num;
		return opt_tls(arg, query);
	}
}

static int opt_notls_ocsp_stapling(const char *arg, void *query)
{
	query_t *q = query;

	q->tls.ocsp_stapling = 0;

	return KNOT_EOK;
}

static int opt_https(const char *arg, void *query)
{
#ifdef LIBNGHTTP2
	query_t *q = query;

	q->https.enable = true;

	if (arg != NULL) {
		char *resource = strstr(arg, "://");
		if (resource == NULL) {
			resource = (char *)arg;
		} else {
			resource += 3;  // strlen("://")
			if (*resource == '\0') {
				ERR("invalid +https=%s\n", arg);
				return KNOT_EINVAL;
			}
		}

		char *tmp_path = strchr(resource, '/');
		if (tmp_path) {
			free(q->https.path);
			q->https.path = strdup(tmp_path);

			if (tmp_path != resource) {
				free(q->tls.hostname);
				q->tls.hostname = strndup(resource, (size_t)(tmp_path - resource));
			}
			return opt_tls(arg, query);
		} else {
			return opt_tls_hostname(arg, query);
		}

	}

	return opt_tls(arg, query);

#else
	return KNOT_ENOTSUP;
#endif //LIBNGHTTP2
}

static int opt_nohttps(const char *arg, void *query)
{
#ifdef LIBNGHTTP2
	query_t *q = query;

	https_params_clean(&q->https);

	return opt_notls(arg, query);
#else
	return KNOT_ENOTSUP;
#endif //LIBNGHTTP2
}

static int opt_https_get(const char *arg, void *query)
{
#ifdef LIBNGHTTP2
	query_t *q = query;

	q->https.method = GET;

	return opt_https(arg, query);
#else
	return KNOT_ENOTSUP;
#endif //LIBNGHTTP2
}

static int opt_nohttps_get(const char *arg, void *query)
{
#ifdef LIBNGHTTP2
	query_t *q = query;

	q->https.method = POST;

	return KNOT_EOK;
#else
	return KNOT_ENOTSUP;
#endif
}

static int opt_nsid(const char *arg, void *query)
{
	query_t *q = query;

	q->nsid = true;

	return KNOT_EOK;
}

static int opt_nonsid(const char *arg, void *query)
{
	query_t *q = query;

	q->nsid = false;

	return KNOT_EOK;
}

static int opt_bufsize(const char *arg, void *query)
{
	query_t *q = query;

	uint16_t num = 0;
	if (str_to_u16(arg, &num) != KNOT_EOK) {
		ERR("invalid +bufsize=%s\n", arg);
		return KNOT_EINVAL;
	}

	// Disable EDNS if zero bufsize.
	if (num == 0) {
		q->udp_size = -1;
	} else if (num < KNOT_WIRE_HEADER_SIZE) {
		q->udp_size = KNOT_WIRE_HEADER_SIZE;
	} else {
		q->udp_size = num;
	}

	return KNOT_EOK;
}

static int opt_nobufsize(const char *arg, void *query)
{
	query_t *q = query;

	q->udp_size = -1;

	return KNOT_EOK;
}

static int opt_cookie(const char *arg, void *query)
{
	query_t *q = query;

	if (arg != NULL) {
		uint8_t *input = NULL;
		size_t input_len;

		int ret = hex_decode(arg, &input, &input_len);
		if (ret != KNOT_EOK) {
			ERR("invalid +cookie=%s\n", arg);
			return KNOT_EINVAL;
		}

		if (input_len < KNOT_EDNS_COOKIE_CLNT_SIZE) {
			ERR("too short client +cookie=%s\n", arg);
			free(input);
			return KNOT_EINVAL;
		}
		q->cc.len = KNOT_EDNS_COOKIE_CLNT_SIZE;
		memcpy(q->cc.data, input, q->cc.len);

		input_len -= q->cc.len;
		if (input_len > 0) {
			if (input_len < KNOT_EDNS_COOKIE_SRVR_MIN_SIZE) {
				ERR("too short server +cookie=%s\n", arg);
				free(input);
				return KNOT_EINVAL;
			}
			if (input_len > KNOT_EDNS_COOKIE_SRVR_MAX_SIZE) {
				ERR("too long server +cookie=%s\n", arg);
				free(input);
				return KNOT_EINVAL;
			}
			q->sc.len = input_len;
			memcpy(q->sc.data, input + q->cc.len, q->sc.len);
		}

		free(input);
	} else {
		q->cc.len = KNOT_EDNS_COOKIE_CLNT_SIZE;

		int ret = dnssec_random_buffer(q->cc.data, q->cc.len);
		if (ret != DNSSEC_EOK) {
			return knot_error_from_libdnssec(ret);
		}
	}

	return KNOT_EOK;
}

static int opt_nocookie(const char *arg, void *query)
{
	query_t *q = query;
	q->cc.len = 0;
	q->sc.len = 0;
	return KNOT_EOK;
}

static int opt_badcookie(const char *arg, void *query)
{
	query_t *q = query;
	q->badcookie = BADCOOKIE_RETRY_MAX;
	return KNOT_EOK;
}

static int opt_nobadcookie(const char *arg, void *query)
{
	query_t *q = query;
	q->badcookie = 0;
	return KNOT_EOK;
}

static int opt_padding(const char *arg, void *query)
{
	query_t *q = query;

	if (arg == NULL) {
		q->padding = -2;
		return KNOT_EOK;
	} else {
		uint16_t num = 0;
		if (str_to_u16(arg, &num) != KNOT_EOK) {
			ERR("invalid +padding=%s\n", arg);
			return KNOT_EINVAL;
		}

		q->padding = num;
		return KNOT_EOK;
	}
}

static int opt_nopadding(const char *arg, void *query)
{
	query_t *q = query;

	q->padding = -3;

	return KNOT_EOK;
}

static int opt_alignment(const char *arg, void *query)
{
	query_t *q = query;

	if (arg == NULL) {
		q->alignment = DEFAULT_ALIGNMENT_SIZE;
		return KNOT_EOK;
	} else {
		uint16_t num = 0;
		if (str_to_u16(arg, &num) != KNOT_EOK || num < 2) {
			ERR("invalid +alignment=%s\n", arg);
			return KNOT_EINVAL;
		}

		q->alignment = num;
		return KNOT_EOK;
	}
}

static int opt_noalignment(const char *arg, void *query)
{
	query_t *q = query;

	q->alignment = 0;

	return KNOT_EOK;
}

static int opt_subnet(const char *arg, void *query)
{
	query_t *q = query;

	char         *sep = NULL;
	const size_t arg_len = strlen(arg);
	const char   *arg_end = arg + arg_len;
	size_t       addr_len = 0;

	// Separate address and network mask.
	if ((sep = strchr(arg, '/')) != NULL) {
		addr_len = sep - arg;
	} else {
		addr_len = arg_len;
	}

	// Check IP address.

	struct sockaddr_storage ss = { 0 };
	struct addrinfo hints = { .ai_flags = AI_NUMERICHOST };
	struct addrinfo *ai = NULL;

	char *addr_str = strndup(arg, addr_len);
	if (getaddrinfo(addr_str, NULL, &hints, &ai) != 0) {
		free(addr_str);
		ERR("invalid address +subnet=%s\n", arg);
		return KNOT_EINVAL;
	}

	memcpy(&ss, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);
	free(addr_str);

	if (knot_edns_client_subnet_set_addr(&q->subnet, &ss) != KNOT_EOK) {
		ERR("invalid address +subnet=%s\n", arg);
		return KNOT_EINVAL;
	}

	// Parse network mask.
	const char *mask = arg;
	if (mask + addr_len < arg_end) {
		mask += addr_len + 1;
		uint8_t num = 0;
		if (str_to_u8(mask, &num) != KNOT_EOK || num > q->subnet.source_len) {
			ERR("invalid network mask +subnet=%s\n", arg);
			return KNOT_EINVAL;
		}
		q->subnet.source_len = num;
	}

	return KNOT_EOK;
}

static int opt_nosubnet(const char *arg, void *query)
{
	query_t *q = query;

	q->subnet.family = AF_UNSPEC;

	return KNOT_EOK;
}

static int opt_edns(const char *arg, void *query)
{
	query_t *q = query;

	if (arg == NULL) {
		q->edns = 0;
		return KNOT_EOK;
	} else {
		uint8_t num = 0;
		if (str_to_u8(arg, &num) != KNOT_EOK) {
			ERR("invalid +edns=%s\n", arg);
			return KNOT_EINVAL;
		}

		q->edns = num;
		return KNOT_EOK;
	}
}

static int opt_noedns(const char *arg, void *query)
{
	query_t *q = query;

	q->edns = -1;
	opt_nodoflag(arg, query);
	opt_nonsid(arg, query);
	opt_nobufsize(arg, query);
	opt_nocookie(arg, query);
	opt_nopadding(arg, query);
	opt_noalignment(arg, query);
	opt_nosubnet(arg, query);

	return KNOT_EOK;
}

static int opt_timeout(const char *arg, void *query)
{
	query_t *q = query;

	if (params_parse_wait(arg, &q->wait) != KNOT_EOK) {
		ERR("invalid +timeout=%s\n", arg);
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int opt_notimeout(const char *arg, void *query)
{
	query_t *q = query;

	(void)params_parse_wait("0", &q->wait);

	return KNOT_EOK;
}

static int opt_retry(const char *arg, void *query)
{
	query_t *q = query;

	if (str_to_u32(arg, &q->retries) != KNOT_EOK) {
		ERR("invalid +retry=%s\n", arg);
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int opt_noretry(const char *arg, void *query)
{
	query_t *q = query;

	q->retries = 0;

	return KNOT_EOK;
}

static int parse_ednsopt(const char *arg, ednsopt_t **opt_ptr)
{
	errno = 0;
	char *end = NULL;
	unsigned long code = strtoul(arg, &end, 10);
	if (errno != 0 || arg == end || code > UINT16_MAX) {
		return KNOT_EINVAL;
	}

	size_t length = 0;
	uint8_t *data = NULL;
	if (end[0] == ':') {
		if (end[1] != '\0') {
			int ret = hex_decode(end + 1, &data, &length);
			if (ret != KNOT_EOK) {
				return ret;
			}
			if (length > UINT16_MAX) {
				free(data);
				return KNOT_ERANGE;
			}
		}
	} else if (end[0] != '\0') {
		return KNOT_EINVAL;
	}

	ednsopt_t *opt = ednsopt_create(code, length, data);
	if (opt == NULL) {
		free(data);
		return KNOT_ENOMEM;
	}

	*opt_ptr = opt;
	return KNOT_EOK;
}

static int opt_ednsopt(const char *arg, void *query)
{
	query_t *q = query;

	ednsopt_t *opt = NULL;
	int ret = parse_ednsopt(arg, &opt);
	if (ret != KNOT_EOK) {
		ERR("invalid +ednsopt=%s\n", arg);
		return KNOT_EINVAL;
	}

	add_tail(&q->edns_opts, &opt->n);

	return KNOT_EOK;
}

static int opt_noednsopt(const char *arg, void *query)
{
	query_t *q = query;

	ednsopt_list_deinit(&q->edns_opts);

	return KNOT_EOK;
}

static int opt_noidn(const char *arg, void *query)
{
	query_t *q = query;

	q->idn = false;
	q->style.style.ascii_to_idn = NULL;

	return KNOT_EOK;
}

static const param_t kdig_opts2[] = {
	{ "multiline",      ARG_NONE,     opt_multiline },
	{ "nomultiline",    ARG_NONE,     opt_nomultiline },

	{ "short",          ARG_NONE,     opt_short },
	{ "noshort",        ARG_NONE,     opt_noshort },

	{ "generic",        ARG_NONE,     opt_generic },
	{ "nogeneric",      ARG_NONE,     opt_nogeneric },

	{ "aaflag",         ARG_NONE,     opt_aaflag },
	{ "noaaflag",       ARG_NONE,     opt_noaaflag },

	{ "tcflag",         ARG_NONE,     opt_tcflag },
	{ "notcflag",       ARG_NONE,     opt_notcflag },

	{ "rdflag",         ARG_NONE,     opt_rdflag },
	{ "nordflag",       ARG_NONE,     opt_nordflag },

	{ "recurse",        ARG_NONE,     opt_rdflag },
	{ "norecurse",      ARG_NONE,     opt_nordflag },

	{ "raflag",         ARG_NONE,     opt_raflag },
	{ "noraflag",       ARG_NONE,     opt_noraflag },

	{ "zflag",          ARG_NONE,     opt_zflag },
	{ "nozflag",        ARG_NONE,     opt_nozflag },

	{ "adflag",         ARG_NONE,     opt_adflag },
	{ "noadflag",       ARG_NONE,     opt_noadflag },

	{ "cdflag",         ARG_NONE,     opt_cdflag },
	{ "nocdflag",       ARG_NONE,     opt_nocdflag },

	{ "dnssec",         ARG_NONE,     opt_doflag },
	{ "nodnssec",       ARG_NONE,     opt_nodoflag },

	{ "all",            ARG_NONE,     opt_all },
	{ "noall",          ARG_NONE,     opt_noall },

	{ "qr",             ARG_NONE,     opt_qr },
	{ "noqr",           ARG_NONE,     opt_noqr },

	{ "header",         ARG_NONE,     opt_header },
	{ "noheader",       ARG_NONE,     opt_noheader },

	{ "comments",       ARG_NONE,     opt_comments },
	{ "nocomments",     ARG_NONE,     opt_nocomments },

	{ "opt",            ARG_NONE,     opt_opt },
	{ "noopt",          ARG_NONE,     opt_noopt },

	{ "opttext",        ARG_NONE,     opt_opttext },
	{ "noopttext",      ARG_NONE,     opt_noopttext },

	{ "question",       ARG_NONE,     opt_question },
	{ "noquestion",     ARG_NONE,     opt_noquestion },

	{ "answer",         ARG_NONE,     opt_answer },
	{ "noanswer",       ARG_NONE,     opt_noanswer },

	{ "authority",      ARG_NONE,     opt_authority },
	{ "noauthority",    ARG_NONE,     opt_noauthority },

	{ "additional",     ARG_NONE,     opt_additional },
	{ "noadditional",   ARG_NONE,     opt_noadditional },

	{ "tsig",           ARG_NONE,     opt_tsig },
	{ "notsig",         ARG_NONE,     opt_notsig },

	{ "stats",          ARG_NONE,     opt_stats },
	{ "nostats",        ARG_NONE,     opt_nostats },

	{ "class",          ARG_NONE,     opt_class },
	{ "noclass",        ARG_NONE,     opt_noclass },

	{ "ttl",            ARG_NONE,     opt_ttl },
	{ "nottl",          ARG_NONE,     opt_nottl },

	{ "crypto",         ARG_NONE,     opt_crypto },
	{ "nocrypto",       ARG_NONE,     opt_nocrypto },

	{ "tcp",            ARG_NONE,     opt_tcp },
	{ "notcp",          ARG_NONE,     opt_notcp },

	{ "fastopen",       ARG_NONE,     opt_fastopen },
	{ "nofastopen",     ARG_NONE,     opt_nofastopen },

	{ "ignore",         ARG_NONE,     opt_ignore },
	{ "noignore",       ARG_NONE,     opt_noignore },

	{ "keepopen",       ARG_NONE,     opt_keepopen },
	{ "nokeepopen",     ARG_NONE,     opt_nokeepopen },

	{ "tls",            ARG_NONE,     opt_tls },
	{ "notls",          ARG_NONE,     opt_notls },

	{ "tls-ca",         ARG_OPTIONAL, opt_tls_ca },
	{ "notls-ca",       ARG_NONE,     opt_notls_ca },

	{ "tls-pin",        ARG_REQUIRED, opt_tls_pin },
	{ "notls-pin",      ARG_NONE,     opt_notls_pin },

	{ "tls-hostname",   ARG_REQUIRED, opt_tls_hostname },
	{ "notls-hostname", ARG_NONE,     opt_notls_hostname },

	{ "tls-sni",        ARG_REQUIRED, opt_tls_sni },
	{ "notls-sni",      ARG_NONE,     opt_notls_sni },

	{ "tls-keyfile",    ARG_REQUIRED, opt_tls_keyfile },
	{ "notls-keyfile",  ARG_NONE,     opt_notls_keyfile },

	{ "tls-certfile",   ARG_REQUIRED, opt_tls_certfile },
	{ "notls-certfile", ARG_NONE,     opt_notls_certfile },

	{ "tls-ocsp-stapling",   ARG_OPTIONAL, opt_tls_ocsp_stapling },
	{ "notls-ocsp-stapling", ARG_NONE,     opt_notls_ocsp_stapling },

	{ "https",          ARG_OPTIONAL, opt_https },
	{ "nohttps",        ARG_NONE,     opt_nohttps },

	{ "https-get",      ARG_NONE,     opt_https_get },
	{ "nohttps-get",    ARG_NONE,     opt_nohttps_get },

	{ "nsid",           ARG_NONE,     opt_nsid },
	{ "nonsid",         ARG_NONE,     opt_nonsid },

	{ "bufsize",        ARG_REQUIRED, opt_bufsize },
	{ "nobufsize",      ARG_NONE,     opt_nobufsize },

	{ "padding",        ARG_OPTIONAL, opt_padding },
	{ "nopadding",      ARG_NONE,     opt_nopadding },

	{ "alignment",      ARG_OPTIONAL, opt_alignment },
	{ "noalignment",    ARG_NONE,     opt_noalignment },

	{ "subnet",         ARG_REQUIRED, opt_subnet },
	{ "nosubnet",       ARG_NONE,     opt_nosubnet },

	// Obsolete aliases.
	{ "client",         ARG_REQUIRED, opt_subnet },
	{ "noclient",       ARG_NONE,     opt_nosubnet },

	{ "edns",           ARG_OPTIONAL, opt_edns },
	{ "noedns",         ARG_NONE,     opt_noedns },

	{ "timeout",        ARG_REQUIRED, opt_timeout },
	{ "notimeout",      ARG_NONE,     opt_notimeout },

	{ "retry",          ARG_REQUIRED, opt_retry },
	{ "noretry",        ARG_NONE,     opt_noretry },

	{ "cookie",         ARG_OPTIONAL, opt_cookie },
	{ "nocookie",       ARG_NONE,     opt_nocookie },

	{ "badcookie",      ARG_NONE,     opt_badcookie },
	{ "nobadcookie",    ARG_NONE,     opt_nobadcookie },

	{ "ednsopt",        ARG_REQUIRED, opt_ednsopt },
	{ "noednsopt",      ARG_NONE,     opt_noednsopt },

	/* "idn" doesn't work since it must be called before query creation. */
	{ "noidn",          ARG_NONE,     opt_noidn },

	{ NULL }
};

query_t *query_create(const char *owner, const query_t *conf)
{
	// Create output structure.
	query_t *query = calloc(1, sizeof(query_t));

	if (query == NULL) {
		DBG_NULL;
		return NULL;
	}

	// Initialization with defaults or with reference query.
	if (conf == NULL) {
		query->conf = NULL;
		query->local = NULL;
		query->operation = OPERATION_QUERY;
		query->ip = IP_ALL;
		query->protocol = PROTO_ALL;
		query->fastopen = false;
		query->port = strdup("");
		query->udp_size = -1;
		query->retries = DEFAULT_RETRIES_DIG;
		query->wait = DEFAULT_TIMEOUT_DIG;
		query->ignore_tc = false;
		query->class_num = -1;
		query->type_num = -1;
		query->serial = -1;
		query->notify = false;
		query->flags = DEFAULT_FLAGS_DIG;
		query->style = DEFAULT_STYLE_DIG;
		query->idn = true;
		query->nsid = false;
		query->edns = -1;
		query->cc.len = 0;
		query->sc.len = 0;
		query->badcookie = BADCOOKIE_RETRY_MAX;
		query->padding = -1;
		query->alignment = 0;
		tls_params_init(&query->tls);
		//query->tsig_key
		query->subnet.family = AF_UNSPEC;
		ednsopt_list_init(&query->edns_opts);
#if USE_DNSTAP
		query->dt_reader = NULL;
		query->dt_writer = NULL;
#endif // USE_DNSTAP
	} else {
		*query = *conf;
		query->conf = conf;
		if (conf->local != NULL) {
			query->local = srv_info_create(conf->local->name,
			                               conf->local->service);
			if (query->local == NULL) {
				query_free(query);
				return NULL;
			}
		} else {
			query->local = NULL;
		}
		query->port = strdup(conf->port);
		tls_params_copy(&query->tls, &conf->tls);
		https_params_copy(&query->https, &conf->https);
		if (conf->tsig_key.name != NULL) {
			int ret = knot_tsig_key_copy(&query->tsig_key,
			                             &conf->tsig_key);
			if (ret != KNOT_EOK) {
				query_free(query);
				return NULL;
			}
		}

		int ret = ednsopt_list_dup(&query->edns_opts, &conf->edns_opts);
		if (ret != KNOT_EOK) {
			query_free(query);
			return NULL;
		}

#if USE_DNSTAP
		query->dt_reader = conf->dt_reader;
		query->dt_writer = conf->dt_writer;
#endif // USE_DNSTAP
	}

	// Initialize list of servers.
	init_list(&query->servers);

	// Set the query owner if any.
	if (owner != NULL) {
		if ((query->owner = strdup(owner)) == NULL) {
			query_free(query);
			return NULL;
		}
	}

	// Check dynamic allocation.
	if (query->port == NULL) {
		query_free(query);
		return NULL;
	}

	return query;
}

void query_free(query_t *query)
{
	node_t *n, *nxt;

	if (query == NULL) {
		DBG_NULL;
		return;
	}

	// Cleanup servers.
	WALK_LIST_DELSAFE(n, nxt, query->servers) {
		srv_info_free((srv_info_t *)n);
	}

	// Cleanup local address.
	if (query->local != NULL) {
		srv_info_free(query->local);
	}

	tls_params_clean(&query->tls);
	https_params_clean(&query->https);

	// Cleanup signing key.
	knot_tsig_key_deinit(&query->tsig_key);

	// Cleanup EDNS options.
	ednsopt_list_deinit(&query->edns_opts);

#if USE_DNSTAP
	if (query->dt_reader != NULL) {
		dt_reader_free(query->dt_reader);
	}
	if (query->dt_writer != NULL) {
		// Global writer can be shared!
		if (query->conf == NULL ||
		    query->conf->dt_writer != query->dt_writer) {
			dt_writer_free(query->dt_writer);
		}
	}
#endif // USE_DNSTAP

	free(query->owner);
	free(query->port);
	free(query);
}

ednsopt_t *ednsopt_create(uint16_t code, uint16_t length, uint8_t *data)
{
	ednsopt_t *opt = calloc(1, sizeof(*opt));
	if (opt == NULL) {
		return NULL;
	}

	opt->code = code;
	opt->length = length;
	opt->data = data;

	return opt;
}

ednsopt_t *ednsopt_dup(const ednsopt_t *opt)
{
	ednsopt_t *dup = calloc(1, sizeof(*opt));
	if (dup == NULL) {
		return NULL;
	}

	dup->code = opt->code;
	dup->length = opt->length;
	dup->data = memdup(opt->data, opt->length);
	if (dup->data == NULL) {
		free(dup);
		return NULL;
	}

	return dup;
}

void ednsopt_free(ednsopt_t *opt)
{
	if (opt == NULL) {
		return;
	}

	free(opt->data);
	free(opt);
}

void ednsopt_list_init(list_t *list)
{
	init_list(list);
}

void ednsopt_list_deinit(list_t *list)
{
	node_t *n, *next;
	WALK_LIST_DELSAFE(n, next, *list) {
		ednsopt_t *opt = (ednsopt_t *)n;
		ednsopt_free(opt);
	}

	init_list(list);
}

int ednsopt_list_dup(list_t *dest, const list_t *src)
{
	list_t backup = *dest;
	init_list(dest);

	node_t *n;
	WALK_LIST(n, *src) {
		ednsopt_t *opt = (ednsopt_t *)n;
		ednsopt_t *dup = ednsopt_dup(opt);
		if (dup == NULL) {
			ednsopt_list_deinit(dest);
			*dest = backup;
			return KNOT_ENOMEM;
		}

		add_tail(dest, &dup->n);
	}

	return KNOT_EOK;
}

bool ednsopt_list_empty(const list_t *list)
{
	return EMPTY_LIST(*list);
}

int kdig_init(kdig_params_t *params)
{
	if (params == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	memset(params, 0, sizeof(*params));

	params->stop = false;

	// Initialize list of queries.
	init_list(&params->queries);

	// Create config query.
	if ((params->config = query_create(NULL, NULL)) == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

void kdig_clean(kdig_params_t *params)
{
	node_t *n, *nxt;

	if (params == NULL) {
		DBG_NULL;
		return;
	}

	// Clean up queries.
	WALK_LIST_DELSAFE(n, nxt, params->queries) {
		query_free((query_t *)n);
	}

	// Clean up config.
	query_free(params->config);

	// Clean up the structure.
	memset(params, 0, sizeof(*params));
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

static int parse_keyfile(const char *value, query_t *query)
{
	knot_tsig_key_deinit(&query->tsig_key);

	if (knot_tsig_key_init_file(&query->tsig_key, value) != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int parse_local(const char *value, query_t *query)
{
	srv_info_t *local = parse_nameserver(value, "0");
	if (local == NULL) {
		return KNOT_EINVAL;
	}

	if (query->local != NULL) {
		srv_info_free(query->local);
	}

	query->local = local;

	return KNOT_EOK;
}

static int parse_name(const char *value, list_t *queries, const query_t *conf)
{
	query_t	*query = NULL;
	char	*ascii_name = (char *)value;
	char	*fqd_name = NULL;

	if (value != NULL) {
		if (conf->idn) {
			ascii_name = name_from_idn(value);
			if (ascii_name == NULL) {
				return KNOT_EINVAL;
			}
		}

		// If name is not FQDN, append trailing dot.
		fqd_name = get_fqd_name(ascii_name);

		if (conf->idn) {
			free(ascii_name);
		}
	}

	// Create new query.
	query = query_create(fqd_name, conf);

	free(fqd_name);

	if (query == NULL) {
		return KNOT_ENOMEM;
	}

	// Add new query to the queries.
	add_tail(queries, (node_t *)query);

	return KNOT_EOK;
}

static int parse_port(const char *value, query_t *query)
{
	char **port;

	// Set current server port (last or query default).
	if (list_size(&query->servers) > 0) {
		srv_info_t *server = TAIL(query->servers);
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

static int parse_reverse(const char *value, list_t *queries, const query_t *conf)
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
	add_tail(queries, (node_t *)query);

	return KNOT_EOK;
}

static int parse_server(const char *value, kdig_params_t *params)
{
	query_t *query;

	// Set current query (last or config).
	if (list_size(&params->queries) > 0) {
		query = TAIL(params->queries);
	} else {
		query = params->config;
	}

	if (params_parse_server(value, &query->servers, query->port) != KNOT_EOK) {
		ERR("invalid server @%s\n", value);
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int parse_tsig(const char *value, query_t *query)
{
	knot_tsig_key_deinit(&query->tsig_key);

	if (knot_tsig_key_init_str(&query->tsig_key, value) != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int parse_type(const char *value, query_t *query)
{
	uint16_t rtype;
	int64_t  serial;
	bool     notify;

	if (params_parse_type(value, &rtype, &serial, &notify) != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	query->type_num = rtype;
	query->serial = serial;
	query->notify = notify;

	// If NOTIFY, reset default RD flag.
	if (query->notify) {
		query->flags.rd_flag = false;
	}

	return KNOT_EOK;
}

#if USE_DNSTAP
static int parse_dnstap_output(const char *value, query_t *query)
{
	if (query->dt_writer != NULL) {
		if (query->conf == NULL ||
		    query->conf->dt_writer != query->dt_writer) {
			dt_writer_free(query->dt_writer);
		}
	}

	query->dt_writer = dt_writer_create(value, "kdig " PACKAGE_VERSION);
	if (query->dt_writer == NULL) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int parse_dnstap_input(const char *value, query_t *query)
{
	// Just in case, shouldn't happen.
	if (query->dt_reader != NULL) {
		dt_reader_free(query->dt_reader);
	}

	query->dt_reader = dt_reader_create(value);
	if (query->dt_reader == NULL) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}
#endif // USE_DNSTAP

static void complete_servers(query_t *query, const query_t *conf)
{
	node_t *n;
	char *def_port;

	// Decide which default port use.
	if (strlen(query->port) > 0) {
		def_port = query->port;
	} else if (strlen(conf->port) > 0) {
		def_port = conf->port;
	} else if (query->https.enable) {
		def_port = DEFAULT_DNS_HTTPS_PORT;
	} else if (query->tls.enable) {
		def_port = DEFAULT_DNS_TLS_PORT;
	} else {
		def_port = DEFAULT_DNS_PORT;
	}

	// Complete specified nameservers if any.
	if (list_size(&query->servers) > 0) {
		WALK_LIST(n, query->servers) {
			srv_info_t *s = (srv_info_t *)n;

			// If the port isn't specified yet use the default one.
			if (strlen(s->service) == 0) {
				free(s->service);
				s->service = strdup(def_port);
				if (s->service == NULL) {
					WARN("can't set port %s\n", def_port);
					return;
				}
			}

			// Use server name as hostname for TLS if necessary.
			if (query->tls.enable && query->tls.hostname == NULL &&
			    (query->tls.system_ca || !EMPTY_LIST(query->tls.ca_files))) {
				query->tls.hostname = strdup(s->name);
			}
		}
	// Use servers from config if any.
	} else if (list_size(&conf->servers) > 0) {
		WALK_LIST(n, conf->servers) {
			srv_info_t *s = (srv_info_t *)n;
			char     *port = def_port;

			// If the port is already specified, use it.
			if (strlen(s->service) > 0) {
				port = s->service;
			}

			srv_info_t *server = srv_info_create(s->name, port);
			if (server == NULL) {
				WARN("can't set nameserver %s port %s\n",
				     s->name, s->service);
				return;
			}
			add_tail(&query->servers, (node_t *)server);

			// Use server name as hostname for TLS if necessary.
			if (query->tls.enable && query->tls.hostname == NULL &&
			    (query->tls.system_ca || !EMPTY_LIST(query->tls.ca_files))) {
				query->tls.hostname = strdup(s->name);
			}
		}
	// Use system specific.
	} else {
		get_nameservers(&query->servers, def_port);
	}
}

static bool compare_servers(list_t *s1, list_t *s2)
{
	if (list_size(s1) != list_size(s2)) {
		return false;
	}

	node_t *n1, *n2 = HEAD(*s2);
	WALK_LIST(n1, *s1) {
		srv_info_t *i1 = (srv_info_t *)n1, *i2 = (srv_info_t *)n2;
		if (strcmp(i1->service, i2->service) != 0 ||
		    strcmp(i1->name, i2->name) != 0)
		{
			return false;
		}
		n2 = n2->next;
	}
	return true;
}

void complete_queries(list_t *queries, const query_t *conf)
{
	node_t  *n;

	if (queries == NULL || conf == NULL) {
		DBG_NULL;
		return;
	}

	// If there is no query, add default query: NS to ".".
	if (list_size(queries) == 0) {
		query_t *q = query_create(".", conf);
		if (q == NULL) {
			WARN("can't create query . NS IN\n");
			return;
		}
		q->class_num = KNOT_CLASS_IN;
		q->type_num = KNOT_RRTYPE_NS;
		add_tail(queries, (node_t *)q);
	}

	WALK_LIST(n, *queries) {
		query_t *q = (query_t *)n;
		query_t *q_prev = (HEAD(*queries) != n) ? (query_t *)n->prev : NULL;

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
				q->serial = conf->serial;
			} else {
				q->type_num = KNOT_RRTYPE_A;
			}
		}

		// Set zone transfer if any.
		if (q->type_num == KNOT_RRTYPE_AXFR ||
		    q->type_num == KNOT_RRTYPE_IXFR) {
			q->operation = OPERATION_XFR;
		}

		// No retries for TCP.
		if (q->protocol == PROTO_TCP) {
			q->retries = 0;
		}

		// Complete nameservers list.
		complete_servers(q, conf);

		// Check if using previous connection makes sense.
		if (q_prev != NULL && q_prev->keepopen &&
		    (get_socktype(q->protocol, q->type_num) !=
		     get_socktype(q_prev->protocol, q_prev->type_num) ||
		     q->https.enable != q_prev->https.enable ||
		     q->tls.enable != q_prev->tls.enable ||
		     strcmp(q->port, q_prev->port) != 0 ||
		     !compare_servers(&q->servers, &q_prev->servers)))
		{
			WARN("connection parameters mismatch for query (%s), "
			     "ignoring keepopen\n", q->owner);
			q_prev->keepopen = false;
		}
	}
}

static void print_help(void)
{
	printf("Usage: %s [-4] [-6] [-d] [-b address] [-c class] [-p port]\n"
	       "            [-q name] [-t type] [-x address] [-k keyfile]\n"
	       "            [-y [algo:]keyname:key] [-E tapfile] [-G tapfile]\n"
	       "            name [type] [class] [@server]\n"
	       "\n"
	       "       +[no]multiline             Wrap long records to more lines.\n"
	       "       +[no]short                 Show record data only.\n"
	       "       +[no]generic               Use generic representation format.\n"
	       "       +[no]aaflag                Set AA flag.\n"
	       "       +[no]tcflag                Set TC flag.\n"
	       "       +[no]rdflag                Set RD flag.\n"
	       "       +[no]recurse               Same as +[no]rdflag\n"
	       "       +[no]raflag                Set RA flag.\n"
	       "       +[no]zflag                 Set zero flag bit.\n"
	       "       +[no]adflag                Set AD flag.\n"
	       "       +[no]cdflag                Set CD flag.\n"
	       "       +[no]dnssec                Set DO flag.\n"
	       "       +[no]all                   Show all packet sections.\n"
	       "       +[no]qr                    Show query packet.\n"
	       "       +[no]header                Show packet header.\n"
	       "       +[no]comments              Show commented section names.\n"
	       "       +[no]opt                   Show EDNS pseudosection.\n"
	       "       +[no]opttext               Try to show unknown EDNS options as text.\n"
	       "       +[no]question              Show question section.\n"
	       "       +[no]answer                Show answer section.\n"
	       "       +[no]authority             Show authority section.\n"
	       "       +[no]additional            Show additional section.\n"
	       "       +[no]tsig                  Show TSIG pseudosection.\n"
	       "       +[no]stats                 Show trailing packet statistics.\n"
	       "       +[no]class                 Show DNS class.\n"
	       "       +[no]ttl                   Show TTL value.\n"
	       "       +[no]crypto                Show binary parts of RRSIGs and DNSKEYs.\n"
	       "       +[no]tcp                   Use TCP protocol.\n"
	       "       +[no]fastopen              Use TCP Fast Open.\n"
	       "       +[no]ignore                Don't use TCP automatically if truncated.\n"
	       "       +[no]keepopen              Don't close the TCP connection to be reused.\n"
	       "       +[no]tls                   Use TLS with Opportunistic privacy profile.\n"
	       "       +[no]tls-ca[=FILE]         Use TLS with Out-Of-Band privacy profile.\n"
	       "       +[no]tls-pin=BASE64        Use TLS with pinned certificate.\n"
	       "       +[no]tls-hostname=STR      Use TLS with remote server hostname.\n"
	       "       +[no]tls-sni=STR           Use TLS with Server Name Indication.\n"
	       "       +[no]tls-keyfile=FILE      Use TLS with a client keyfile.\n"
	       "       +[no]tls-certfile=FILE     Use TLS with a client certfile.\n"
	       "       +[no]tls-ocsp-stapling[=H] Use TLS with a valid stapled OCSP response for the\n"
	       "                                  server certificate (%u or specify hours).\n"
#ifdef LIBNGHTTP2
	       "       +[no]https[=URL]           Use HTTPS protocol. It's also possible to specify\n"
	       "                                  URL as [authority][/path] where query will be sent.\n"
	       "       +[no]https-get             Use HTTPS protocol with GET method instead of POST.\n"
#endif
	       "       +[no]nsid                  Request NSID.\n"
	       "       +[no]bufsize=B             Set EDNS buffer size.\n"
	       "       +[no]padding[=N]           Pad with EDNS(0) (default or specify size).\n"
	       "       +[no]alignment[=N]         Pad with EDNS(0) to blocksize (%u or specify size).\n"
	       "       +[no]subnet=SUBN           Set EDNS(0) client subnet addr/prefix.\n"
	       "       +[no]edns[=N]              Use EDNS(=version).\n"
	       "       +[no]timeout=T             Set wait for reply interval in seconds.\n"
	       "       +[no]retry=N               Set number of retries.\n"
	       "       +[no]cookie=HEX            Attach EDNS(0) cookie to the query.\n"
	       "       +[no]badcookie             Repeat a query with the correct cookie.\n"
	       "       +[no]ednsopt=CODE[:HEX]    Set custom EDNS option.\n"
	       "       +noidn                     Disable IDN transformation.\n"
	       "\n"
	       "       -h, --help                 Print the program help.\n"
	       "       -V, --version              Print the program version.\n",
	       PROGRAM_NAME, DEFAULT_TLS_OCSP_STAPLING / 3600, DEFAULT_ALIGNMENT_SIZE);
}

static int parse_opt1(const char *opt, const char *value, kdig_params_t *params,
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
	case 'b':
		if (val == NULL) {
			ERR("missing address\n");
			return KNOT_EINVAL;
		}

		if (parse_local(val, query) != KNOT_EOK) {
			ERR("bad address %s\n", val);
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

		print_help();
		params->stop = true;
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
	case 'k':
		if (val == NULL) {
			ERR("missing filename\n");
			return KNOT_EINVAL;
		}

		if (parse_keyfile(val, query) != KNOT_EOK) {
			ERR("bad keyfile %s\n", value);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
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
		// Allow empty QNAME.
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
	case 'V':
		if (len > 1) {
			ERR("invalid option -%s\n", opt);
			return KNOT_ENOTSUP;
		}

		print_version(PROGRAM_NAME);
		params->stop = true;
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
	case 'y':
		if (val == NULL) {
			ERR("missing key\n");
			return KNOT_EINVAL;
		}

		if (parse_tsig(val, query) != KNOT_EOK) {
			ERR("bad key %s\n", value);
			return KNOT_EINVAL;
		}
		*index += add;
		break;
	case 'E':
#if USE_DNSTAP
		if (val == NULL) {
			ERR("missing filename\n");
			return KNOT_EINVAL;
		}

		if (parse_dnstap_output(val, query) != KNOT_EOK) {
			ERR("unable to open dnstap output file %s\n", val);
			return KNOT_EINVAL;
		}
		*index += add;
#else
		ERR("no dnstap support but -E specified\n");
		return KNOT_EINVAL;
#endif // USE_DNSTAP
		break;
	case 'G':
#if USE_DNSTAP
		if (val == NULL) {
			ERR("missing filename\n");
			return KNOT_EINVAL;
		}

		query = query_create(NULL, params->config);
		if (query == NULL) {
			return KNOT_ENOMEM;
		}

		if (parse_dnstap_input(val, query) != KNOT_EOK) {
			ERR("unable to open dnstap input file %s\n", val);
			query_free(query);
			return KNOT_EINVAL;
		}

		query->operation = OPERATION_LIST_DNSTAP;
		add_tail(&params->queries, (node_t *)query);

		*index += add;
#else
		ERR("no dnstap support but -G specified\n");
		return KNOT_EINVAL;
#endif // USE_DNSTAP
		break;
	case '-':
		if (strcmp(opt, "-help") == 0) {
			print_help();
			params->stop = true;
		} else if (strcmp(opt, "-version") == 0) {
			print_version(PROGRAM_NAME);
			params->stop = true;
		} else {
			ERR("invalid option: -%s\n", opt);
			return KNOT_ENOTSUP;
		}
		break;
	default:
		ERR("invalid option: -%s\n", opt);
		return KNOT_ENOTSUP;
	}

	return KNOT_EOK;
}

static int parse_opt2(const char *value, kdig_params_t *params)
{
	query_t *query;

	// Set current query (last or config).
	if (list_size(&params->queries) > 0) {
		query = TAIL(params->queries);
	} else {
		query = params->config;
	}

	// Get option name.
	const char *arg_sep = "=";
	size_t opt_len = strcspn(value, arg_sep);
	if (opt_len < 1) {
		ERR("invalid option: +%s\n", value);
		return KNOT_ENOTSUP;
	}

	// Get option argument if any.
	const char *arg = NULL;
	const char *rest = value + opt_len;
	if (strlen(rest) > 0) {
		arg = rest + strspn(rest, arg_sep);
	}

	// Check if the given option is supported.
	bool unique;
	int ret = best_param(value, opt_len, kdig_opts2, &unique);
	if (ret < 0) {
		ERR("invalid option: +%s\n", value);
		return KNOT_ENOTSUP;
	} else if (!unique) {
		ERR("ambiguous option: +%s\n", value);
		return KNOT_ENOTSUP;
	}

	// Check argument presence.
	switch (kdig_opts2[ret].arg) {
	case ARG_NONE:
		if (arg != NULL && *arg != '\0') {
			WARN("superfluous option argument: +%s\n", value);
		}
		break;
	case ARG_REQUIRED:
		if (arg == NULL) {
			ERR("missing argument: +%s\n", value);
			return KNOT_EFEWDATA;
		}
		// FALLTHROUGH
	case ARG_OPTIONAL:
		if (arg != NULL && *arg == '\0') {
			ERR("empty argument: +%s\n", value);
			return KNOT_EFEWDATA;
		}
		break;
	}

	// Call option handler.
	return kdig_opts2[ret].handler(arg, query);
}

static int parse_token(const char *value, kdig_params_t *params)
{
	query_t *query;

	// Set current query (last or config).
	if (list_size(&params->queries) > 0) {
		query = TAIL(params->queries);
	} else {
		query = params->config;
	}

	// Try to guess the meaning of the token.
	if (strlen(value) == 0) {
		ERR("invalid empty parameter\n");
	} else if (parse_type(value, query) == KNOT_EOK) {
		return KNOT_EOK;
	} else if (parse_class(value, query) == KNOT_EOK) {
		return KNOT_EOK;
	} else if (parse_name(value, &params->queries, params->config) == KNOT_EOK) {
		return KNOT_EOK;
	} else {
		ERR("invalid parameter: %s\n", value);
	}

	return KNOT_EINVAL;
}

int kdig_parse(kdig_params_t *params, int argc, char *argv[])
{
	if (params == NULL || argv == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Initialize parameters.
	if (kdig_init(params) != KNOT_EOK) {
		return KNOT_ERROR;
	}

#ifdef LIBIDN
	// Set up localization.
	if (setlocale(LC_CTYPE, "") == NULL) {
		WARN("can't setlocale, disabling IDN\n");
		params->config->idn = false;
		params->config->style.style.ascii_to_idn = NULL;
	}
#endif

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
			if (params->stop) {
				return KNOT_EOK;
			}
			break;
		case KNOT_ENOTSUP:
			print_help();
		default: // Fall through.
			return ret;
		}
	}

	// Complete missing data in queries based on defaults.
	complete_queries(&params->queries, params->config);

	return KNOT_EOK;
}
