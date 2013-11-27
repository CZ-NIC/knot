#include <config.h>

#include "libknot/nameserver/axfr.h"
#include "libknot/nameserver/ns_proc_query.h"
#include "libknot/util/debug.h"
#include "common/descriptor.h"
#include "common/lists.h"

struct axfr_proc {
	hattrie_iter_t *i;
	unsigned cur_rrset;
	list_t nodes;
};

static int axfr_put(knot_pkt_t *pkt, const knot_rrset_t *rrset)
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
		ret = axfr_put(pkt, rrset[i]);
		if (ret != KNOT_EOK) { /* Keep for continuing. */
			state->cur_rrset = i;
			return ret;
		}
	}

	state->cur_rrset = 0;
	return ret;
}

static int answer_put_nodes(knot_pkt_t *pkt, struct axfr_proc *state)
{
	/* Put responses. */
	int ret = KNOT_EOK;
	while(!hattrie_iter_finished(state->i)) {
		knot_node_t *node = (knot_node_t *)*hattrie_iter_val(state->i);
		ret = put_rrsets(pkt, node, state);
		if (ret != KNOT_EOK) {
			break;
		}
		hattrie_iter_next(state->i);
	}

	/* Finished all nodes. */
	return ret;
}

static int answer_pkt(knot_pkt_t *pkt, struct query_data *qdata)
{

	int ret = KNOT_EOK;
	mm_ctx_t *mm = qdata->mm;
	struct axfr_proc *state = qdata->ext;
	knot_zone_contents_t *zone = pkt->zone->contents;
	knot_rrset_t *soa_rr = knot_node_get_rrset(zone->apex, KNOT_RRTYPE_SOA);

	/* Prepend SOA on first packet. */
	if (state == NULL) {
		ret = axfr_put(pkt, soa_rr);
		if (ret != KNOT_EOK) {
			return ret;
		}
		/* Begin zone iterator. */
		state = mm->alloc(mm->ctx, sizeof(struct axfr_proc));
		if (state == NULL) {
			return KNOT_ENOMEM;
		}
		
		memset(state, 0, sizeof(struct axfr_proc));
		init_list(&state->nodes);
		ptrlist_add(&state->nodes, zone->nodes, mm);
		ptrlist_add(&state->nodes, zone->nsec3_nodes, mm);
		qdata->ext = state;
	} 

	/* Put zone contents and then NSEC3-related contents. */
	while (!EMPTY_LIST(state->nodes)) {
		ptrnode_t *head = HEAD(state->nodes);
		if (state->i == NULL) {
			state->i = hattrie_iter_begin(head->d, true);
		}
		ret = answer_put_nodes(pkt, state);
		if (ret == KNOT_EOK) { /* Finished. */
			hattrie_iter_free(state->i);
			state->i = NULL;
			rem_node((node_t *)head);
			mm->free(head);
		} else { /* Packet full or error. */
			break;
		}
	}	

	/* Append SOA on last packet. */
	if (ret == KNOT_EOK) {
		ret = axfr_put(pkt, soa_rr);
	}
	/* Check if finished or not. */
	if (ret != KNOT_ESPACE) {
		/* Finished successfuly or fatal error. */
		ptrlist_free(&state->nodes, mm);
		mm->free(state);
		qdata->ext = NULL;
	}

	return ret;
}

int axfr_answer(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	assert(pkt);
	assert(ns);
	assert(qdata);


	/* Check zone state. */
	switch(knot_zone_state(pkt->zone)) {
	case KNOT_EOK:
		break;
	case KNOT_ENOENT:
		qdata->rcode = KNOT_RCODE_NOTAUTH;
		return NS_PROC_FAIL;
	default:
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return NS_PROC_FAIL;
	}

	/* Answer current packet (or continue). */
	int ret = answer_pkt(pkt, qdata);
	switch(ret) {
	case KNOT_ESPACE: /* Couldn't write more, send packet and continue. */
		return NS_PROC_FULL; /* Check for more. */
	case KNOT_EOK:    /* Last response. */
		break;
	default:          /* Generic error. */
		dbg_ns("%s: answered with ret = %s\n", __func__, knot_strerror(ret));
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return NS_PROC_FAIL;
	}

	return NS_PROC_FINISH;
}
