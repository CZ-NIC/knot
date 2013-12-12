#include <config.h>

#include "libknot/nameserver/ixfr.h"
#include "libknot/nameserver/axfr.h"
#include "libknot/nameserver/internet.h"
#include "libknot/nameserver/ns_proc_query.h"
#include "libknot/util/debug.h"
#include "libknot/rdata.h"
#include "knot/server/zones.h"
#include "common/descriptor.h"

/*! \brief Current IXFR answer sections. */
enum {
	SOA_REMOVE = 0,
	REMOVE,
	SOA_ADD,
	ADD
};

/*! \brief Extended structure for IXFR processing. */
struct ixfr_proc {
	struct xfr_proc proc;
	node_t *cur;
	unsigned state;
	knot_changesets_t *changesets;
};

/*! \brief Helper macro for putting RRs into packet. */
#define IXFR_SAFE_PUT(pkt, rr) \
	ret = knot_pkt_put((pkt), 0, (rr), KNOT_PF_NOTRUNC); \
	if (ret != KNOT_EOK) { \
		return ret; \
	}

static int ixfr_put_rrlist(knot_pkt_t *pkt, struct ixfr_proc *ixfr, list_t *list)
{
	assert(pkt);
	assert(ixfr);
	assert(list);

	/* If at the beginning, fetch first RR. */
	int ret = KNOT_EOK;
	if (ixfr->cur == NULL) {
		ixfr->cur = HEAD(*list);
	}
	/* Now iterate until it hits the last one,
	 * this is done without for() loop because we can
	 * rejoin the iteration at any point. */
	knot_rr_ln_t *rr_item = NULL;
	while(ixfr->cur != NULL) {
		rr_item = (knot_rr_ln_t *)ixfr->cur;
		if (knot_rrset_rdata_rr_count(rr_item->rr) > 0) {
			IXFR_SAFE_PUT(pkt, rr_item->rr);
		} else {
			dbg_ns("%s: empty RR %p, skipping\n", __func__, rr_item->rr);
		}

		ixfr->cur = ixfr->cur->next;
	}
	return ret;
}


/*!
 * \brief Process single changeset.
 * \note Keep in mind that this function must be able to resume processing,
 *       for example if it fills a packet and returns ESPACE, it is called again
 *       with next empty answer and it must resume the processing exactly where
 *       it's left off.
 */
static int ixfr_process_item(knot_pkt_t *pkt, const void *item, struct xfr_proc *xfer)
{
	int ret = KNOT_EOK;
	struct ixfr_proc *ixfr = (struct ixfr_proc *)xfer;
	knot_changeset_t *chgset = (knot_changeset_t *)item;

	/* Put former SOA. */
	if (ixfr->state == SOA_REMOVE) {
		IXFR_SAFE_PUT(pkt, chgset->soa_from);
		dbg_ns("%s: put 'REMOVE' SOA\n", __func__);
		ixfr->state = REMOVE;
	}

	/* Put REMOVE RRSets. */
	if (ixfr->state == REMOVE) {
		ret = ixfr_put_rrlist(pkt, ixfr, &chgset->remove);
		if (ret != KNOT_EOK) {
			return ret;
		}
		dbg_ns("%s: put 'REMOVE' RRs\n", __func__);
		ixfr->state = SOA_ADD;
	}

	/* Put next SOA. */
	if (ixfr->state == SOA_ADD) {
		IXFR_SAFE_PUT(pkt, chgset->soa_to);
		dbg_ns("%s: put 'ADD' SOA\n", __func__);
		ixfr->state = ADD;
	}

	/* Put REMOVE RRSets. */
	if (ixfr->state == ADD) {
		ret = ixfr_put_rrlist(pkt, ixfr, &chgset->add);
		if (ret != KNOT_EOK) {
			return ret;
		}
		dbg_ns("%s: put 'ADD' RRs\n", __func__);
		ixfr->state = SOA_REMOVE;
	}

	return ret;
}

#undef IXFR_SAFE_PUT

static int ixfr_load_chsets(knot_changesets_t **chgsets, const knot_zone_t *zone,
			    const knot_rrset_t *their_soa)
{
	assert(chgsets);
	assert(zone);

	/* Compare serials. */
	const knot_node_t *apex = zone->contents->apex;
	const knot_rrset_t *our_soa = knot_node_rrset(apex, KNOT_RRTYPE_SOA);
	uint32_t serial_to = knot_rdata_soa_serial(our_soa);
	uint32_t serial_from = knot_rdata_soa_serial(their_soa);
	int ret = ns_serial_compare(serial_to, serial_from);
	if (ret <= 0) { /* We have older/same age zone. */
		return KNOT_EUPTODATE;
	}

	*chgsets = knot_changesets_create();
	if (*chgsets == NULL) {
		return KNOT_ENOMEM;
	}

	/*! \todo This is a candidate for function relocation. */
	ret = zones_load_changesets(zone, *chgsets, serial_from, serial_to);
	if (ret != KNOT_EOK) {
		knot_changesets_free(chgsets);
	}

	return ret;
}

static int ixfr_answer_init(struct query_data *qdata)
{

	/* Check zone state. */
	NS_NEED_VALID_ZONE(qdata, KNOT_RCODE_NOTAUTH);
	/* Need IXFR query type. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_IXFR, KNOT_RCODE_FORMERR);
	/* Need SOA authority record. */
	const knot_pktsection_t *authority = knot_pkt_section(qdata->pkt, KNOT_AUTHORITY);
	const knot_rrset_t *their_soa = authority->rr[0];
	if (authority->count < 1 || knot_rrset_type(their_soa) != KNOT_RRTYPE_SOA) {
		qdata->rcode = KNOT_RCODE_FORMERR;
		return NS_PROC_FAIL;
	}
	/* SOA needs to match QNAME. */
	NS_NEED_QNAME(qdata, their_soa->owner, KNOT_RCODE_FORMERR);

	/* Compare serials. */
	knot_changesets_t *chgsets = NULL;
	int ret = ixfr_load_chsets(&chgsets, qdata->zone, their_soa);
	if (ret != KNOT_EOK) {
		/*! \todo AXFR fallback. */
		return ret;
	}

	/* Initialize transfer processing. */
	mm_ctx_t *mm = qdata->mm;
	struct ixfr_proc *xfer = mm->alloc(mm->ctx, sizeof(struct ixfr_proc));
	if (xfer == NULL) {
		knot_changesets_free(&chgsets);
		return KNOT_ENOMEM;
	}
	memset(xfer, 0, sizeof(struct ixfr_proc));
	init_list(&xfer->proc.nodes);
	qdata->ext = xfer;

	/* Put all changesets to process. */
	xfer->changesets = chgsets;
	knot_changeset_t *chs = NULL;
	WALK_LIST(chs, chgsets->sets) {
		ptrlist_add(&xfer->proc.nodes, chs, mm);
		dbg_ns("%s: preparing %u -> %u\n", __func__, chs->serial_from, chs->serial_to);
	}

	return KNOT_EOK;
}

int ixfr_answer_soa(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	dbg_ns("%s: answering IXFR/SOA\n", __func__);
	if (pkt == NULL || ns == NULL || qdata == NULL) {
		return NS_PROC_FAIL;
	}

	/* Check zone state. */
	NS_NEED_VALID_ZONE(qdata, KNOT_RCODE_NOTAUTH);

	/* Guaranteed to have zone contents. */
	const knot_node_t *apex = qdata->zone->contents->apex;
	const knot_rrset_t *soa_rr = knot_node_rrset(apex, KNOT_RRTYPE_SOA);
	int ret = knot_pkt_put(pkt, 0, soa_rr, 0);
	if (ret != KNOT_EOK) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return NS_PROC_FAIL;
	}

	return NS_PROC_FINISH;
}

int ixfr_answer(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	if (pkt == NULL || ns == NULL || qdata == NULL) {
		return NS_PROC_FAIL;
	}

	int ret = KNOT_EOK;
	mm_ctx_t *mm = qdata->mm;
	
	/*! \todo Log messages. */

	/* Initialize on first call. */
	if (qdata->ext == NULL) {
		ret = ixfr_answer_init(qdata);
		dbg_ns("%s: init => %s\n", __func__, knot_strerror(ret));
		switch(ret) {
		case KNOT_EOK:      /* OK */
			break;
		case KNOT_EUPTODATE: /* Our zone is same age/older, send SOA. */
			return ixfr_answer_soa(pkt, ns, qdata);
		case KNOT_ERANGE:   /* No history -> AXFR. */
		case KNOT_ENOENT:
			return axfr_answer(pkt, ns, qdata);
		default:            /* Server errors. */
			return NS_PROC_FAIL;
		}
	}

	/* Answer current packet (or continue). */
	struct ixfr_proc *ixfr = (struct ixfr_proc*)qdata->ext;
	ret = xfr_process_list(pkt, &ixfr_process_item, qdata);
	switch(ret) {
	case KNOT_ESPACE: /* Couldn't write more, send packet and continue. */
		return NS_PROC_FULL; /* Check for more. */
	case KNOT_EOK:    /* Last response. */
		dbg_ns("%s: finished IXFR, %u pkts, %.01fkB\n", __func__,
		       ixfr->proc.npkts, ixfr->proc.nbytes/1024.0);
		ret = NS_PROC_FINISH;
		break;
	default:          /* Generic error. */
		dbg_ns("%s: answered with ret = %s\n", __func__, knot_strerror(ret));
		ret = NS_PROC_FAIL;
		break;
	}

	/* Finished successfuly or fatal error. */
	ptrlist_free(&ixfr->proc.nodes, mm);
	knot_changesets_free(&ixfr->changesets);
	mm->free(qdata->ext);
	qdata->ext = NULL;

	return ret;
}
