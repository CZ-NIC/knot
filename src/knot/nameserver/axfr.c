/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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


#include "knot/nameserver/axfr.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/process_query.h"
#include "common/debug.h"
#include "common/descriptor.h"
#include "common/lists.h"
#include "knot/server/zones.h"

/* AXFR context. */
struct axfr_proc {
	struct xfr_proc proc;
	hattrie_iter_t *i;
	unsigned cur_rrset;
};

static int put_rrsets(knot_pkt_t *pkt, knot_node_t *node, struct axfr_proc *state)
{
	int ret = KNOT_EOK;
	int i = state->cur_rrset;
	int rrset_count = knot_node_rrset_count(node);
	unsigned flags = KNOT_PF_NOTRUNC;
	
	/* Append all RRs. */
	for (;i < rrset_count; ++i) {
		knot_rrset_t rrset = NODE_RR_INIT_N(node, i);
		if (rrset.type == KNOT_RRTYPE_SOA) {
			continue;
		}
		ret = knot_pkt_put(pkt, 0, &rrset, flags);

		/* If something failed, remember the current RR for later. */
		if (ret != KNOT_EOK) {
			state->cur_rrset = i;
			return ret;
		}
	}

	state->cur_rrset = 0;
	return ret;
}

static int axfr_process_node_tree(knot_pkt_t *pkt, const void *item, struct xfr_proc *state)
{
	struct axfr_proc *axfr = (struct axfr_proc*)state;

	if (axfr->i == NULL) {
		axfr->i = hattrie_iter_begin(item, true);
	}

	/* Put responses. */
	int ret = KNOT_EOK;
	knot_node_t *node = NULL;
	while(!hattrie_iter_finished(axfr->i)) {
		node = (knot_node_t *)*hattrie_iter_val(axfr->i);
		ret = put_rrsets(pkt, node, axfr);
		if (ret != KNOT_EOK) {
			break;
		}
		hattrie_iter_next(axfr->i);
	}

	/* Finished all nodes. */
	if (ret == KNOT_EOK) {
		hattrie_iter_free(axfr->i);
		axfr->i = NULL;
	}
	return ret;
}

static void axfr_answer_cleanup(struct query_data *qdata)
{
	struct xfr_proc *axfr = (struct xfr_proc *)qdata->ext;
	mm_ctx_t *mm = qdata->mm;

	ptrlist_free(&axfr->nodes, mm);
	mm->free(axfr);

	/* Allow zone changes (finished). */
	rcu_read_unlock();
}

static int axfr_answer_init(struct query_data *qdata)
{
	assert(qdata);

	/* Create transfer processing context. */
	mm_ctx_t *mm = qdata->mm;
	knot_zone_contents_t *zone = qdata->zone->contents;
	struct xfr_proc *xfer = mm->alloc(mm->ctx, sizeof(struct axfr_proc));
	if (xfer == NULL) {
		return KNOT_ENOMEM;
	}
	memset(xfer, 0, sizeof(struct axfr_proc));
	init_list(&xfer->nodes);

	/* Put data to process. */
	gettimeofday(&xfer->tstamp, NULL);
	ptrlist_add(&xfer->nodes, zone->nodes, mm);
	/* Put NSEC3 data if exists. */
	if (!knot_zone_tree_is_empty(zone->nsec3_nodes)) {
		ptrlist_add(&xfer->nodes, zone->nsec3_nodes, mm);
	}

	/* Set up cleanup callback. */
	qdata->ext = xfer;
	qdata->ext_cleanup = &axfr_answer_cleanup;

	/* No zone changes during multipacket answer (unlocked in axfr_answer_cleanup) */
	rcu_read_lock();

	return KNOT_EOK;
}

int xfr_process_list(knot_pkt_t *pkt, xfr_put_cb process_item, struct query_data *qdata)
{

	int ret = KNOT_EOK;
	mm_ctx_t *mm = qdata->mm;
	struct xfr_proc *xfer = qdata->ext;
	knot_zone_contents_t *zone = qdata->zone->contents;
	knot_rrset_t soa_rr = NODE_RR_INIT(zone->apex, KNOT_RRTYPE_SOA);

	/* Prepend SOA on first packet. */
	if (xfer->npkts == 0) {
		ret = knot_pkt_put(pkt, 0, &soa_rr, KNOT_PF_NOTRUNC);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Process all items in the list. */
	while (!EMPTY_LIST(xfer->nodes)) {
		ptrnode_t *head = HEAD(xfer->nodes);
		ret = process_item(pkt, head->d, xfer);
		if (ret == KNOT_EOK) { /* Finished. */
			/* Complete change set. */
			rem_node((node_t *)head);
			mm->free(head);
		} else { /* Packet full or other error. */
			break;
		}
	}

	/* Append SOA on last packet. */
	if (ret == KNOT_EOK) {
		ret = knot_pkt_put(pkt, 0, &soa_rr, KNOT_PF_NOTRUNC);
	}

	/* Update counters. */
	xfer->npkts  += 1;
	xfer->nbytes += pkt->size;

	return ret;
}

/* AXFR-specific logging (internal, expects 'qdata' variable set). */
#define AXFR_LOG(severity, msg...) \
	ANSWER_LOG(severity, qdata, "Outgoing AXFR", msg)

int axfr_answer(knot_pkt_t *pkt, struct query_data *qdata)
{
	assert(pkt);
	assert(qdata);

	int ret = KNOT_EOK;
	struct timeval now = {0};

	/* If AXFR is disabled, respond with NOTIMPL. */
	if (qdata->param->proc_flags & NS_QUERY_NO_AXFR) {
		qdata->rcode = KNOT_RCODE_NOTIMPL;
		return NS_PROC_FAIL;
	}

	/* Initialize on first call. */
	if (qdata->ext == NULL) {

		/* Check valid zone, transaction security and contents. */
		NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);
		NS_NEED_AUTH(qdata->zone->xfr_out, qdata);
		NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL); /* Check expiration. */

		ret = axfr_answer_init(qdata);
		if (ret != KNOT_EOK) {
			AXFR_LOG(LOG_ERR, "Failed to start (%s).", knot_strerror(ret));
			return ret;
		} else {
			AXFR_LOG(LOG_INFO, "Started (serial %u).", knot_zone_serial(qdata->zone->contents));
		}
	}

	/* Reserve space for TSIG. */
	knot_pkt_reserve(pkt, tsig_wire_maxsize(qdata->sign.tsig_key));

	/* Answer current packet (or continue). */
	struct xfr_proc *xfer = qdata->ext;
	ret = xfr_process_list(pkt, &axfr_process_node_tree, qdata);
	switch(ret) {
	case KNOT_ESPACE: /* Couldn't write more, send packet and continue. */
		return NS_PROC_FULL; /* Check for more. */
	case KNOT_EOK:    /* Last response. */
		gettimeofday(&now, NULL);
		AXFR_LOG(LOG_INFO, "Finished in %.02fs (%u messages, ~%.01fkB).",
		         time_diff(&xfer->tstamp, &now) / 1000.0,
		         xfer->npkts, xfer->nbytes / 1024.0);
		return NS_PROC_DONE;
		break;
	default:          /* Generic error. */
		AXFR_LOG(LOG_ERR, "%s", knot_strerror(ret));
		return NS_PROC_FAIL;
	}
}

int axfr_process_answer(knot_pkt_t *pkt, knot_ns_xfr_t *xfr)
{
	/*
	 * Here we assume that 'xfr' contains TSIG information
	 * and the digest of the query sent to the master or the previous
	 * digest.
	 */

	dbg_ns("ns_process_axfrin: incoming packet, wire size: %zu\n",
	       xfr->wire_size);
	int ret = xfrin_process_axfr_packet(pkt, xfr,
	                                    (knot_zone_contents_t **)&xfr->data);
	if (ret > 0) { // transfer finished
		dbg_ns("ns_process_axfrin: AXFR finished, zone created.\n");

		gettimeofday(&xfr->t_end, NULL);

		/*
		 * Adjust zone so that node count is set properly and nodes are
		 * marked authoritative / delegation point.
		 */
		knot_zone_contents_t *zone = (knot_zone_contents_t *)xfr->data;
		assert(zone != NULL);
		log_zone_info("%s Serial %u -> %u\n", xfr->msg,
		              knot_zone_serial(xfr->zone->contents),
		              knot_zone_serial(zone));

		dbg_ns_verb("ns_process_axfrin: adjusting zone.\n");
		int rc = knot_zone_contents_adjust_full(zone, NULL, NULL);
		if (rc != KNOT_EOK) {
			return rc;
		}

		// save the zone contents to the xfr->data
		xfr->new_contents = zone;
		xfr->flags |= XFR_FLAG_AXFR_FINISHED;
	}

	return ret;
}

#undef AXFR_LOG
