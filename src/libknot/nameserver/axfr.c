#include <config.h>

#include "libknot/nameserver/axfr.h"
#include "libknot/nameserver/internet.h"
#include "libknot/nameserver/ns_proc_query.h"
#include "libknot/util/debug.h"
#include "common/descriptor.h"
#include "common/lists.h"
#include "knot/server/zones.h"

struct axfr_proc {
	struct xfr_proc proc;
	hattrie_iter_t *i;
	unsigned cur_rrset;
};

static int put_rrset_and_rrsig(knot_pkt_t *pkt, const knot_rrset_t *rrset)
{
	const unsigned flags = KNOT_PF_NOTRUNC;
	int ret = knot_pkt_put(pkt, 0, rrset, flags);
	if (ret == KNOT_EOK && rrset->rrsigs) {
		ret = knot_pkt_put(pkt, 0, rrset, flags);
	} 
		
	return ret;
}

static int put_rrsets(knot_pkt_t *pkt, knot_node_t *node, struct axfr_proc *state)
{
	int ret = KNOT_EOK;
	
	/* Append all RRs. */
	unsigned i = state->cur_rrset;
	unsigned rrset_count = knot_node_rrset_count(node);
	const knot_rrset_t **rrset = knot_node_rrsets_no_copy(node);
	for (;i < rrset_count; ++i) {
		/* Skip SOA and empty nodes. */	
		if (knot_rrset_type(rrset[i]) == KNOT_RRTYPE_SOA ||
			knot_rrset_rdata_rr_count(rrset[i]) == 0) {
			continue;
		}

		/* Put into packet. */
		ret = put_rrset_and_rrsig(pkt, rrset[i]);
		if (ret != KNOT_EOK) { /* Keep for continuing. */
			state->cur_rrset = i;
			return ret;
		}
	}

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

int axfr_answer(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	assert(pkt);
	assert(ns);
	assert(qdata);

	int ret = KNOT_EOK;
	mm_ctx_t *mm = qdata->mm;
	
	/*! \todo Log messages. */

	/* Initialize on first call. */
	if (qdata->ext == NULL) {

		/* Check zone state. */
		NS_NEED_VALID_ZONE(qdata, KNOT_RCODE_NOTAUTH);
		
		/* Need valid transaction security. */
		zonedata_t *zone_data = (zonedata_t *)knot_zone_data(qdata->zone);
		NS_NEED_AUTH(zone_data->xfr_out, qdata);
		
		ret = axfr_answer_init(qdata);
		if (ret != KNOT_EOK) {
			dbg_ns("%s: init => %s\n", __func__, knot_strerror(ret));
			return ret;
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
		dbg_ns("%s: finished AXFR, %u pkts, ~%.01fkB\n", __func__,
		       xfer->npkts, xfer->nbytes/1024.0);
		ret = NS_PROC_DONE;
		break;
	default:          /* Generic error. */
		dbg_ns("%s: answered with ret = %s\n", __func__, knot_strerror(ret));
		ret = NS_PROC_FAIL;
		break;
	}

	/* Finished successfuly or fatal error. */
	ptrlist_free(&xfer->nodes, mm);
	mm->free(xfer);
	qdata->ext = NULL;

	return ret;
}
