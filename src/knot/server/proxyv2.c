/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/server/proxyv2.h"

#include "contrib/proxyv2/proxyv2.h"
#include "knot/conf/conf.h"

int proxyv2_header_strip(knot_pkt_t **query,
                         const struct sockaddr_storage *remote,
                         struct sockaddr_storage *new_remote)
{
	conf_t *pconf = conf();
	if (!pconf->cache.srv_proxy_enabled) {
		return KNOT_EDENIED;
	}

	uint8_t *pkt = (*query)->wire;
	size_t pkt_len = (*query)->max_size;

	int offset = proxyv2_header_offset(pkt, pkt_len);
	if (offset <= 0) {
		return KNOT_EMALF;
	}

	/*
	 * Check if the query was sent from an IP address authorized to send
	 * proxied DNS traffic.
	 */
	conf_val_t whitelist_val = conf_get(pconf, C_SRV, C_PROXY_ALLOWLIST);
	if (!conf_addr_range_match(&whitelist_val, remote)) {
		return KNOT_EDENIED;
	}

	/*
	 * Store the provided remote address.
	 */
	int ret = proxyv2_addr_store(pkt, pkt_len, new_remote);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/*
	 * Re-parse the query message using the data in the
	 * packet following the PROXY v2 payload. And replace the original
	 * query with the decapsulated one.
	 */
	knot_pkt_t *q = knot_pkt_new(pkt + offset, pkt_len - offset, &(*query)->mm);
	if (q == NULL) {
		return KNOT_ENOMEM;
	}
	knot_pkt_free(*query);
	*query = q;

	return knot_pkt_parse(q, 0);
}
