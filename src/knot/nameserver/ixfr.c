#include <config.h>

#include "knot/nameserver/ixfr.h"
#include "knot/nameserver/axfr.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/process_query.h"
#include "common/debug.h"
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
	struct query_data *qdata;
	const knot_rrset_t *soa_from, *soa_to;
};

/* IXFR-specific logging (internal, expects 'qdata' variable set). */
#define IXFR_LOG(severity, msg...) \
	ANSWER_LOG(severity, qdata, "Outgoing IXFR", msg)

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
	while(ixfr->cur->next) {
		knot_rr_ln_t *rr_item = (knot_rr_ln_t *)(ixfr->cur);
		if (knot_rrset_rdata_rr_count(rr_item->rr) > 0) {
			IXFR_SAFE_PUT(pkt, rr_item->rr);
		} else {
			dbg_ns("%s: empty RR %p, skipping\n", __func__, rr_item->rr);
		}

		ixfr->cur = ixfr->cur->next;
	}

	ixfr->cur = NULL;
	return ret;
}

/*!
 * \brief Process single changeset.
 * \note Keep in mind that this function must be able to resume processing,
 *       for example if it fills a packet and returns ESPACE, it is called again
 *       with next empty answer and it must resume the processing exactly where
 *       it's left off.
 */
static int ixfr_process_changeset(knot_pkt_t *pkt, const void *item, struct xfr_proc *xfer)
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

	/* Finished change set. */
	struct query_data *qdata = ixfr->qdata; /*< Required for IXFR_LOG() */
	IXFR_LOG(LOG_INFO, "Serial %u -> %u.", chgset->serial_from, chgset->serial_to);

	return ret;
}

#undef IXFR_SAFE_PUT

static int ixfr_load_chsets(knot_changesets_t **chgsets, const zone_t *zone,
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

static int ixfr_query_check(struct query_data *qdata)
{
	/* Check if zone exists. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);

	/* Need IXFR query type. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_IXFR, KNOT_RCODE_FORMERR);
	/* Need SOA authority record. */
	const knot_pktsection_t *authority = knot_pkt_section(qdata->query, KNOT_AUTHORITY);
	const knot_rrset_t *their_soa = authority->rr[0];
	if (authority->count < 1 || knot_rrset_type(their_soa) != KNOT_RRTYPE_SOA) {
		qdata->rcode = KNOT_RCODE_FORMERR;
		return NS_PROC_FAIL;
	}
	/* SOA needs to match QNAME. */
	NS_NEED_QNAME(qdata, their_soa->owner, KNOT_RCODE_FORMERR);

	/* Check transcation security and zone contents. */
	NS_NEED_AUTH(qdata->zone->xfr_out, qdata);
	NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL); /* Check expiration. */

	return NS_PROC_DONE;
}

static void ixfr_answer_cleanup(struct query_data *qdata)
{
	struct ixfr_proc *ixfr = (struct ixfr_proc *)qdata->ext;
	mm_ctx_t *mm = qdata->mm;

	ptrlist_free(&ixfr->proc.nodes, mm);
	knot_changesets_free(&ixfr->changesets);
	mm->free(qdata->ext);
}

static int ixfr_answer_init(struct query_data *qdata)
{
	/* Check IXFR query validity. */
	int state = ixfr_query_check(qdata);
	if (state == NS_PROC_FAIL) {
		if (qdata->rcode == KNOT_RCODE_FORMERR) {
			return KNOT_EMALF;
		} else {
			return KNOT_EDENIED;
		}
	}

	/* Compare serials. */
	const knot_rrset_t *their_soa = knot_pkt_section(qdata->query, KNOT_AUTHORITY)->rr[0];
	knot_changesets_t *chgsets = NULL;
	int ret = ixfr_load_chsets(&chgsets, qdata->zone, their_soa);
	if (ret != KNOT_EOK) {
		dbg_ns("%s: failed to load changesets => %d\n", __func__, ret);
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
	gettimeofday(&xfer->proc.tstamp, NULL);
	init_list(&xfer->proc.nodes);
	xfer->qdata = qdata;

	/* Put all changesets to processing queue. */
	xfer->changesets = chgsets;
	knot_changeset_t *chs = NULL;
	WALK_LIST(chs, chgsets->sets) {
		ptrlist_add(&xfer->proc.nodes, chs, mm);
		dbg_ns("%s: preparing %u -> %u\n", __func__, chs->serial_from, chs->serial_to);
	}

	/* Keep first and last serial. */
	chs = HEAD(chgsets->sets);
	xfer->soa_from = chs->soa_from;
	chs = TAIL(chgsets->sets);
	xfer->soa_to = chs->soa_to;

	/* Set up cleanup callback. */
	qdata->ext = xfer;
	qdata->ext_cleanup = &ixfr_answer_cleanup;

	return KNOT_EOK;
}

static int ixfr_answer_soa(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	dbg_ns("%s: answering IXFR/SOA\n", __func__);
	if (pkt == NULL || ns == NULL || qdata == NULL) {
		return NS_PROC_FAIL;
	}

	/* Check query. */
	int state = ixfr_query_check(qdata);
	if (state == NS_PROC_FAIL) {
		return state; /* Malformed query. */
	}

	/* Reserve space for TSIG. */
	knot_pkt_reserve(pkt, tsig_wire_maxsize(qdata->sign.tsig_key));

	/* Guaranteed to have zone contents. */
	const knot_node_t *apex = qdata->zone->contents->apex;
	const knot_rrset_t *soa_rr = knot_node_rrset(apex, KNOT_RRTYPE_SOA);
	int ret = knot_pkt_put(pkt, 0, soa_rr, 0);
	if (ret != KNOT_EOK) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return NS_PROC_FAIL;
	}

	return NS_PROC_DONE;
}

int ixfr_answer(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	if (pkt == NULL || ns == NULL || qdata == NULL) {
		return NS_PROC_FAIL;
	}

	int ret = KNOT_EOK;
	struct timeval now = {0};
	struct ixfr_proc *ixfr = (struct ixfr_proc*)qdata->ext;

	/* If IXFR is disabled, respond with SOA. */
	if (qdata->param->proc_flags & NS_QUERY_NO_IXFR) {
		return ixfr_answer_soa(pkt, ns, qdata);
	}

	/* Initialize on first call. */
	if (qdata->ext == NULL) {
		ret = ixfr_answer_init(qdata);
		switch(ret) {
		case KNOT_EOK:      /* OK */
			ixfr = (struct ixfr_proc*)qdata->ext;
			IXFR_LOG(LOG_INFO, "Started (serial %u -> %u).",
			         knot_rdata_soa_serial(ixfr->soa_from),
			         knot_rdata_soa_serial(ixfr->soa_to));
			break;
		case KNOT_EUPTODATE: /* Our zone is same age/older, send SOA. */
			IXFR_LOG(LOG_INFO, "Zone is up-to-date.");
			return ixfr_answer_soa(pkt, ns, qdata);
		case KNOT_ERANGE:   /* No history -> AXFR. */
		case KNOT_ENOENT:
			IXFR_LOG(LOG_INFO, "Incomplete history, fallback to AXFR.");
			qdata->packet_type = KNOT_QUERY_AXFR; /* Solve as AXFR. */
			return axfr_answer(pkt, ns, qdata);
		default:            /* Server errors. */
			IXFR_LOG(LOG_ERR, "Failed to start (%s).", knot_strerror(ret));
			return NS_PROC_FAIL;
		}
	}

	/* Reserve space for TSIG. */
	knot_pkt_reserve(pkt, tsig_wire_maxsize(qdata->sign.tsig_key));

	/* Answer current packet (or continue). */
	ret = xfr_process_list(pkt, &ixfr_process_changeset, qdata);
	switch(ret) {
	case KNOT_ESPACE: /* Couldn't write more, send packet and continue. */
		return NS_PROC_FULL; /* Check for more. */
	case KNOT_EOK:    /* Last response. */
		gettimeofday(&now, NULL);
		IXFR_LOG(LOG_INFO, "Finished in %.02fs (%u messages, ~%.01fkB).",
		         time_diff(&ixfr->proc.tstamp, &now) / 1000.0,
		         ixfr->proc.npkts, ixfr->proc.nbytes / 1024.0);
		ret = NS_PROC_DONE;
		break;
	default:          /* Generic error. */
		IXFR_LOG(LOG_ERR, "%s", knot_strerror(ret));
		ret = NS_PROC_FAIL;
		break;
	}

	return ret;
}

#undef IXFR_LOG
