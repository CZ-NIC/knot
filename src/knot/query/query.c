/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/query/query.h"

#include "contrib/wire_ctx.h"
#include "libdnssec/random.h"

void query_init_pkt(knot_pkt_t *pkt)
{
	if (pkt == NULL) {
		return;
	}

	knot_pkt_clear(pkt);
	knot_wire_set_id(pkt->wire, dnssec_random_uint16_t());
}

query_edns_data_t query_edns_data_init(conf_t *conf, int remote_family,
                                       query_edns_opt_t opts)
{
	assert(conf);

	query_edns_data_t edns = {
		.max_payload = remote_family == AF_INET ?
		               conf->cache.srv_udp_max_payload_ipv4 :
		               conf->cache.srv_udp_max_payload_ipv6,
		.do_flag = (opts & QUERY_EDNS_OPT_DO),
		.expire_option = (opts & QUERY_EDNS_OPT_EXPIRE)
	};

	return edns;
}

int query_put_edns(knot_pkt_t *pkt, const query_edns_data_t *edns)
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

	// Add result into the packet

	knot_pkt_begin(pkt, KNOT_ADDITIONAL);

	ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NOCOMP, &opt_rr, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&opt_rr, &pkt->mm);
		return ret;
	}

	return KNOT_EOK;
}
