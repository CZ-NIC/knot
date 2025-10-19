/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/query/query.h"

#include "contrib/wire_ctx.h"
#include "libknot/dnssec/random.h"

void query_init_pkt(knot_pkt_t *pkt)
{
	if (pkt == NULL) {
		return;
	}

	knot_pkt_clear(pkt);
	knot_wire_set_id(pkt->wire, dnssec_random_uint16_t());
}

query_edns_data_t query_edns_data_init(conf_t *conf, const conf_remote_t *remote,
                                       query_edns_opt_t opts)
{
	assert(conf);

	query_edns_data_t edns = {
		.max_payload = remote->addr.ss_family == AF_INET ?
		               conf->cache.srv_udp_max_payload_ipv4 :
		               conf->cache.srv_udp_max_payload_ipv6,
		.no_edns = remote->no_edns,
		.do_flag = (opts & QUERY_EDNS_OPT_DO),
		.expire_option = (opts & QUERY_EDNS_OPT_EXPIRE)
	};

	return edns;
}

int query_put_edns(knot_pkt_t *pkt, const query_edns_data_t *edns, bool padding)
{
	if (!pkt || !edns) {
		return KNOT_EINVAL;
	}

	// Construct EDNS RR

	knot_rrset_t opt_rr = { 0 };
	int ret = knot_edns_init(&opt_rr, edns->max_payload, 0, KNOT_EDNS_VERSION, &pkt->mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (edns->do_flag) {
		knot_edns_set_do(&opt_rr);
	}

	if (edns->expire_option) {
		ret = knot_edns_add_option(&opt_rr, KNOT_EDNS_OPTION_EXPIRE, 0, NULL, &pkt->mm);
		if (ret != KNOT_EOK) {
			knot_rrset_clear(&opt_rr, &pkt->mm);
			return ret;
		}
	}

	if (padding) {
		int padsize = knot_pkt_default_padding_size(pkt, &opt_rr);
		if (padsize > -1) {
			// it's OK to just "reserve" instead of "add" since the padding payload is zeroes
			ret = knot_edns_reserve_option(&opt_rr, KNOT_EDNS_OPTION_PADDING,
			                               padsize, NULL, &pkt->mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	// Add result into the packet

	knot_pkt_begin(pkt, KNOT_ADDITIONAL);

	ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NOCOMP, &opt_rr, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&opt_rr, &pkt->mm);
		return ret;
	}

	return KNOT_EOK;
}
