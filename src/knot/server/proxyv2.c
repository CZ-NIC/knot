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
	 * Re-parse the query message using the data in the
	 * packet following the PROXY v2 payload.
	 */
	knot_pkt_t *q = knot_pkt_new(pkt + offset, pkt_len - offset, &(*query)->mm);

	/*
	 * Check if the calculated offset of the original DNS message is
	 * actually inside the packet received on the wire, and if so, parse
	 * the real DNS query message.
	 */
	int ret = knot_pkt_parse(q, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/*
	 * Store the provided remote address.
	 */
	ret = proxyv2_addr_store(pkt, pkt_len, new_remote);
	if (ret != KNOT_EOK && q->parsed > 0) {
		return ret;
	}

	knot_pkt_free(*query);
	*query = q;

	return KNOT_EOK;
}
