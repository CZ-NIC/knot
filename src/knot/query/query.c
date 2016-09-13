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

#include "knot/query/query.h"

#include <stdint.h>

#include "contrib/wire.h"
#include "contrib/wire_ctx.h"
#include "dnssec/random.h"
#include "knot/conf/conf.h"
#include "libknot/yparser/yptrafo.h"
#include "libknot/rrset.h"

int query_init_pkt(knot_pkt_t *pkt)
{
	if (!pkt) {
		return KNOT_EINVAL;
	}

	knot_pkt_clear(pkt);
	knot_wire_set_id(pkt->wire, dnssec_random_uint16_t());

	return KNOT_EOK;
}

int query_edns_data_init(struct query_edns_data *edns_ptr, conf_t *conf,
                         const knot_dname_t *zone, int remote_family)
{
	if (!edns_ptr || !conf || !zone) {
		return KNOT_EINVAL;
	}

	struct query_edns_data edns = { 0 };

	// Determine max payload

	switch (remote_family) {
	case AF_INET:
		edns.max_payload = conf->cache.srv_max_ipv4_udp_payload;
		break;
	case AF_INET6:
		edns.max_payload = conf->cache.srv_max_ipv6_udp_payload;
		break;
	default:
		return KNOT_EINVAL;
	}

	// Determine custom option

	conf_val_t val = conf_zone_get(conf, C_REQUEST_EDNS_OPTION, zone);
	size_t opt_len = 0;
	const uint8_t *opt_data = conf_data(&val, &opt_len);
	if (opt_data != NULL) {
		wire_ctx_t ctx = wire_ctx_init_const(opt_data, opt_len);
		edns.custom_code = wire_ctx_read_u64(&ctx);
		#warning No boundary check in the yparser API.
		edns.custom_len  = yp_bin_len(ctx.position);
		edns.custom_data = yp_bin(ctx.position);
		if (ctx.error != KNOT_EOK) {
			return KNOT_EINVAL;
		}
	}

	*edns_ptr = edns;
	return KNOT_EOK;
}

int query_put_edns(knot_pkt_t *pkt, const struct query_edns_data *edns)
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

	if (edns->custom_code != 0) {
		ret = knot_edns_add_option(&opt_rr, edns->custom_code,
		                           edns->custom_len, edns->custom_data,
		                           &pkt->mm);
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
