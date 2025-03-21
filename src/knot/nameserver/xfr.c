/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/nameserver/xfr.h"
#include "contrib/mempattern.h"

int xfr_process_list(knot_pkt_t *pkt, xfr_put_cb put, knotd_qdata_t *qdata)
{
	if (pkt == NULL || qdata == NULL || qdata->extra->ext == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	struct xfr_proc *xfer = qdata->extra->ext;

	/* Check if the zone wasn't expired during multi-message transfer. */
	const zone_contents_t *contents = qdata->extra->contents;
	if (contents == NULL) {
		return KNOT_ENOZONE;
	}
	knot_rrset_t soa_rr = node_rrset(contents->apex, KNOT_RRTYPE_SOA);

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
			mm_free(qdata->mm, head);
		} else { /* Packet full or other error. */
			break;
		}
	}

	/* Append SOA on last packet. */
	if (ret == KNOT_EOK) {
		ret = knot_pkt_put(pkt, 0, &soa_rr, KNOT_PF_NOTRUNC);
	}

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
