#include <config.h>

#include "libknot/nameserver/axfr.h"
#include "libknot/nameserver/internet.h"
#include "libknot/nameserver/ns_proc_query.h"
#include "libknot/util/debug.h"
#include "common/descriptor.h"
#include "common/lists.h"
#include "knot/server/zones.h"

/* AXFR context. */
struct axfr_proc {
	struct xfr_proc proc;
	hattrie_iter_t *i;
	unsigned cur_rrset;
	bool cur_rrsig; /* \note Workaround because 'RRSIGS' need to be 'special', jeez. */
};

static int put_rrsets(knot_pkt_t *pkt, knot_node_t *node, struct axfr_proc *state)
{
	int ret = KNOT_EOK;
	unsigned flags = KNOT_PF_NOTRUNC;
	unsigned i = state->cur_rrset;
	unsigned rrset_count = knot_node_rrset_count(node);
	const knot_rrset_t **rrset = knot_node_rrsets_no_copy(node);
	
	/* Append all RRs. */
	for (;i < rrset_count; ++i) {
		/* \note Only RRSIG for SOA, don't add the actual RRSet. */
		if (!state->cur_rrsig && knot_rrset_type(rrset[i]) != KNOT_RRTYPE_SOA) {
			ret = knot_pkt_put(pkt, 0, rrset[i], flags);
		}

		/* Now put the RRSIG (if it exists). */
		if (ret == KNOT_EOK && rrset[i]->rrsigs) {
			/* \note RRSet data is already in the packet,
			 *       now we need only RRSIG. Because RRSIGs are special
			 *       we need to remember that :-( */
			state->cur_rrsig = true;
			ret = knot_pkt_put(pkt, 0, rrset[i]->rrsigs, flags);
		}

		/* If something failed, remember the current RR for later. */
		if (ret != KNOT_EOK) {
			state->cur_rrset = i;
			return ret;
		} else {
			/* RRSIG is in the packet, clear the flag. */
			state->cur_rrsig = false;
		}
	}

	state->cur_rrsig = false;
	state->cur_rrset = 0;
	return ret;
}

static int axfr_process_item(knot_pkt_t *pkt, const void *item, struct xfr_proc *state)
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

static int axfr_answer_init(struct query_data *qdata)
{
	assert(qdata);

	/* Begin zone iterator. */
	mm_ctx_t *mm = qdata->mm;
	knot_zone_contents_t *zone = qdata->zone->contents;
	struct xfr_proc *xfer = mm->alloc(mm->ctx, sizeof(struct axfr_proc));
	if (xfer == NULL) {
		return KNOT_ENOMEM;
	}
	memset(xfer, 0, sizeof(struct axfr_proc));
	init_list(&xfer->nodes);
	gettimeofday(&xfer->tstamp, NULL);
	qdata->ext = xfer;

	/* Put data to process. */
	ptrlist_add(&xfer->nodes, zone->nodes, mm);
	ptrlist_add(&xfer->nodes, zone->nsec3_nodes, mm);
	return KNOT_EOK;
}

int xfr_process_list(knot_pkt_t *pkt, xfr_put_cb process_item, struct query_data *qdata)
{

	int ret = KNOT_EOK;
	mm_ctx_t *mm = qdata->mm;
	struct xfr_proc *xfer = qdata->ext;
	knot_zone_contents_t *zone = qdata->zone->contents;
	knot_rrset_t *soa_rr = knot_node_get_rrset(zone->apex, KNOT_RRTYPE_SOA);

	/* Prepend SOA on first packet. */
	if (xfer->npkts == 0) {
		ret = knot_pkt_put(pkt, 0, soa_rr, KNOT_PF_NOTRUNC);
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
		ret = knot_pkt_put(pkt, 0, soa_rr, KNOT_PF_NOTRUNC);
	}

	/* Update counters. */
	xfer->npkts  += 1;
	xfer->nbytes += pkt->size;

	return ret;
}

/* AXFR-specific logging (internal, expects 'qdata' variable set). */
#define AXFR_LOG(severity, msg...) \
	ANSWER_LOG(severity, qdata, "Outgoing AXFR", msg)

int axfr_answer(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	assert(pkt);
	assert(ns);
	assert(qdata);

	int ret = KNOT_EOK;
	mm_ctx_t *mm = qdata->mm;
	struct timeval now = {0};
	

	/* Initialize on first call. */
	if (qdata->ext == NULL) {

		/* Check zone state. */
		NS_NEED_VALID_ZONE(qdata, KNOT_RCODE_NOTAUTH);
		
		/* Need valid transaction security. */
		zonedata_t *zone_data = (zonedata_t *)knot_zone_data(qdata->zone);
		NS_NEED_AUTH(zone_data->xfr_out, qdata);
		
		ret = axfr_answer_init(qdata);
		if (ret != KNOT_EOK) {
			AXFR_LOG(LOG_ERR, "Failed to start (%s).", knot_strerror(ret));
			return ret;
		} else {
			AXFR_LOG(LOG_INFO, "Started (serial %u).", knot_zone_serial(qdata->zone->contents));
		}
	}
	
	/* Reserve space for TSIG. */
	knot_pkt_tsig_set(pkt, qdata->sign.tsig_key);

	/* Answer current packet (or continue). */
	struct xfr_proc *xfer = qdata->ext;
	ret = xfr_process_list(pkt, &axfr_process_item, qdata);
	switch(ret) {
	case KNOT_ESPACE: /* Couldn't write more, send packet and continue. */
		return NS_PROC_FULL; /* Check for more. */
	case KNOT_EOK:    /* Last response. */
		gettimeofday(&now, NULL);
		AXFR_LOG(LOG_INFO, "Finished in %.02fs (%u messages, ~%.01fkB).",
		         time_diff(&xfer->tstamp, &now) / 1000.0,
		         xfer->npkts, xfer->nbytes / 1024.0);
		ret = NS_PROC_DONE;
		break;
	default:          /* Generic error. */
		AXFR_LOG(LOG_ERR, "%s", knot_strerror(ret));
		ret = NS_PROC_FAIL;
		break;
	}

	/* Finished successfuly or fatal error. */
	ptrlist_free(&xfer->nodes, mm);
	mm->free(xfer);
	qdata->ext = NULL;

	return ret;
}

#undef AXFR_LOG
