/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/nameserver/xfr.h"
#include "contrib/mempattern.h"

int xfr_process_list(knot_pkt_t *pkt, xfr_put_cb put, knotd_qdata_t *qdata)
{
	if (pkt == NULL || qdata == NULL || qdata->extra->ext == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	knot_mm_t *mm = qdata->mm;
	struct xfr_proc *xfer = qdata->extra->ext;

	zone_contents_t *zone = qdata->extra->zone->contents;
	knot_rrset_t soa_rr = node_rrset(zone->apex, KNOT_RRTYPE_SOA);

	/* Prepend SOA on first packet. */
	if (xfer->stats.messages == 0) {
		ret = knot_pkt_put(pkt, 0, &soa_rr, KNOT_PF_NOTRUNC);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Process all items in the list. */
	while (!EMPTY_LIST(xfer->nodes)) {
		ptrnode_t *head = HEAD(xfer->nodes);
		ret = put(pkt, head->d, xfer);
		if (ret == KNOT_EOK) { /* Finished. */
			/* Complete change set. */
			rem_node((node_t *)head);
			mm_free(mm, head);
		} else { /* Packet full or other error. */
			break;
		}
	}

	/* Append SOA on last packet. */
	if (ret == KNOT_EOK) {
		ret = knot_pkt_put(pkt, 0, &soa_rr, KNOT_PF_NOTRUNC);
	}

	/* Update counters. */
	size_t opt_size = knot_rrset_empty(&qdata->opt_rr) ? 0 : knot_rrset_size(&qdata->opt_rr);
	xfr_stats_add(&xfer->stats, pkt->size + opt_size);

	/* If a rrset is larger than the message,
	 * fail to avoid infinite loop of empty messages */
	if (ret == KNOT_ESPACE && pkt->rrset_count < 1) {
		return KNOT_ENOXFR;
	}

	return ret;
}

void xfr_stats_begin(struct xfr_stats *stats)
{
	assert(stats);

	memset(stats, 0, sizeof(*stats));
	stats->begin = time_now();
}

void xfr_stats_add(struct xfr_stats *stats, unsigned bytes)
{
	assert(stats);

	stats->messages += 1;
	stats->bytes += bytes;
}

void xfr_stats_end(struct xfr_stats *stats)
{
	assert(stats);

	stats->end = time_now();
}
