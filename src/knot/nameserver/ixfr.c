#include "knot/nameserver/ixfr.h"
#include "knot/nameserver/axfr.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/process_answer.h"
#include "knot/updates/apply.h"
#include "common/debug.h"
#include "common/descriptor.h"
#include "libknot/util/utils.h"
#include "libknot/rrtype/soa.h"

/* ------------------------ IXFR-out processing ----------------------------- */

/*! \brief IXFR-in processing states. */
enum ixfr_states {
	IXFR_START = 0,  /* IXFR-in starting, expecting final SOA. */
	IXFR_SOA_DEL,    /* Expecting starting SOA. */
	IXFR_SOA_ADD,    /* Expecting ending SOA. */
	IXFR_DEL,        /* Expecting RR to delete. */
	IXFR_ADD,        /* Expecting RR to add. */
	IXFR_DONE        /* Processing done, IXFR-in complete. */
};

/*! \brief Extended structure for IXFR-in/IXFR-out processing. */
struct ixfr_proc {
	struct xfr_proc proc;          /* Generic transfer processing context. */
	node_t *cur;
	int state;                     /* IXFR-in state. */
	changesets_t *changesets;      /* Processed changesets. */
	zone_t *zone;                  /* Modified zone - for journal access. */
	mm_ctx_t *mm;                  /* Memory context for RR allocations. */
	struct query_data *qdata;
	const knot_rrset_t *soa_from;
	const knot_rrset_t *soa_to;
};

/* IXFR-out-specific logging (internal, expects 'qdata' variable set). */
#define IXFROUT_LOG(severity, msg...) \
	QUERY_LOG(severity, qdata, "Outgoing IXFR", msg)

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
		if (rr_item->rr->rrs.rr_count > 0) {
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
static int ixfr_process_changeset(knot_pkt_t *pkt, const void *item,
                                  struct xfr_proc *xfer)
{
	int ret = KNOT_EOK;
	struct ixfr_proc *ixfr = (struct ixfr_proc *)xfer;
	changeset_t *chgset = (changeset_t *)item;

	/* Put former SOA. */
	if (ixfr->state == IXFR_SOA_DEL) {
		IXFR_SAFE_PUT(pkt, chgset->soa_from);
		dbg_ns("%s: put 'REMOVE' SOA\n", __func__);
		ixfr->state = IXFR_DEL;
	}

	/* Put REMOVE RRSets. */
	if (ixfr->state == IXFR_DEL) {
		ret = ixfr_put_rrlist(pkt, ixfr, &chgset->remove);
		if (ret != KNOT_EOK) {
			return ret;
		}
		dbg_ns("%s: put 'REMOVE' RRs\n", __func__);
		ixfr->state = IXFR_SOA_ADD;
	}

	/* Put next SOA. */
	if (ixfr->state == IXFR_SOA_ADD) {
		IXFR_SAFE_PUT(pkt, chgset->soa_to);
		dbg_ns("%s: put 'IXFR_ADD' SOA\n", __func__);
		ixfr->state = IXFR_ADD;
	}

	/* Put REMOVE RRSets. */
	if (ixfr->state == IXFR_ADD) {
		ret = ixfr_put_rrlist(pkt, ixfr, &chgset->add);
		if (ret != KNOT_EOK) {
			return ret;
		}
		dbg_ns("%s: put 'IXFR_ADD' RRs\n", __func__);
		ixfr->state = IXFR_SOA_DEL;
	}

	/* Finished change set. */
	struct query_data *qdata = ixfr->qdata; /*< Required for IXFROUT_LOG() */
	const uint32_t serial_from = knot_soa_serial(&chgset->soa_from->rrs);
	const uint32_t serial_to = knot_soa_serial(&chgset->soa_to->rrs);
	IXFROUT_LOG(LOG_INFO, "Serial %u -> %u.", serial_from, serial_to);

	return ret;
}

#undef IXFR_SAFE_PUT

static int ixfr_load_chsets(changesets_t **chgsets, const zone_t *zone,
			    const knot_rrset_t *their_soa)
{
	assert(chgsets);
	assert(zone);

	/* Compare serials. */
	uint32_t serial_to = zone_contents_serial(zone->contents);
	uint32_t serial_from = knot_soa_serial(&their_soa->rrs);
	int ret = knot_serial_compare(serial_to, serial_from);
	if (ret <= 0) { /* We have older/same age zone. */
		return KNOT_EUPTODATE;
	}

	*chgsets = changesets_create(0);
	if (*chgsets == NULL) {
		return KNOT_ENOMEM;
	}

	ret = journal_load_changesets(zone->conf->ixfr_db, *chgsets,
	                              serial_from, serial_to);
	if (ret != KNOT_EOK) {
		changesets_free(chgsets, NULL);
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
	const knot_rrset_t *their_soa = &authority->rr[0];
	if (authority->count < 1 || their_soa->type != KNOT_RRTYPE_SOA) {
		qdata->rcode = KNOT_RCODE_FORMERR;
		return NS_PROC_FAIL;
	}
	/* SOA needs to match QNAME. */
	NS_NEED_QNAME(qdata, their_soa->owner, KNOT_RCODE_FORMERR);

	/* Check transcation security and zone contents. */
	NS_NEED_AUTH(&qdata->zone->conf->acl.xfr_out, qdata);
	NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL); /* Check expiration. */

	return NS_PROC_DONE;
}

static void ixfr_answer_cleanup(struct query_data *qdata)
{
	struct ixfr_proc *ixfr = (struct ixfr_proc *)qdata->ext;
	mm_ctx_t *mm = qdata->mm;

	ptrlist_free(&ixfr->proc.nodes, mm);
	changesets_free(&ixfr->changesets, NULL);
	mm->free(qdata->ext);

	/* Allow zone changes (finished). */
	rcu_read_unlock();
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
	const knot_rrset_t *their_soa = &knot_pkt_section(qdata->query, KNOT_AUTHORITY)->rr[0];
	changesets_t *chgsets = NULL;
	int ret = ixfr_load_chsets(&chgsets, qdata->zone, their_soa);
	if (ret != KNOT_EOK) {
		dbg_ns("%s: failed to load changesets => %d\n", __func__, ret);
		return ret;
	}

	/* Initialize transfer processing. */
	mm_ctx_t *mm = qdata->mm;
	struct ixfr_proc *xfer = mm->alloc(mm->ctx, sizeof(struct ixfr_proc));
	if (xfer == NULL) {
		changesets_free(&chgsets, NULL);
		return KNOT_ENOMEM;
	}
	memset(xfer, 0, sizeof(struct ixfr_proc));
	gettimeofday(&xfer->proc.tstamp, NULL);
	xfer->state = IXFR_SOA_DEL;
	init_list(&xfer->proc.nodes);
	xfer->qdata = qdata;

	/* Put all changesets to processing queue. */
	xfer->changesets = chgsets;
	changeset_t *chs = NULL;
	WALK_LIST(chs, chgsets->sets) {
		ptrlist_add(&xfer->proc.nodes, chs, mm);
	}

	/* Keep first and last serial. */
	chs = HEAD(chgsets->sets);
	xfer->soa_from = chs->soa_from;
	chs = TAIL(chgsets->sets);
	xfer->soa_to = chs->soa_to;

	/* Set up cleanup callback. */
	qdata->ext = xfer;
	qdata->ext_cleanup = &ixfr_answer_cleanup;

	/* No zone changes during multipacket answer (unlocked in axfr_answer_cleanup) */
	rcu_read_lock();

	return KNOT_EOK;
}

static int ixfr_answer_soa(knot_pkt_t *pkt, struct query_data *qdata)
{
	dbg_ns("%s: answering IXFR/SOA\n", __func__);
	if (pkt == NULL || qdata == NULL) {
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
	const zone_node_t *apex = qdata->zone->contents->apex;
	knot_rrset_t soa_rr = node_rrset(apex, KNOT_RRTYPE_SOA);
	if (knot_rrset_empty(&soa_rr)) {
		return NS_PROC_FAIL;
	}
	int ret = knot_pkt_put(pkt, 0, &soa_rr, 0);
	if (ret != KNOT_EOK) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return NS_PROC_FAIL;
	}

	return NS_PROC_DONE;
}

/* ------------------------- IXFR-in processing ----------------------------- */

/* IXFR-in-specific logging (internal, expects 'adata' variable set). */
#define IXFRIN_LOG(severity, msg...) \
	ANSWER_LOG(severity, adata, "Incoming IXFR", msg)

/*! \brief Cleans up data allocated by IXFR-in processing. */
static void ixfrin_cleanup(struct answer_data *data)
{
	struct ixfr_proc *proc = data->ext;
	if (proc) {
		changesets_free(&proc->changesets, data->mm);
		mm_free(data->mm, proc);
		data->ext = NULL;
	}
}

/*! \brief Initializes IXFR-in processing context. */
static int ixfrin_answer_init(struct answer_data *data)
{
	struct ixfr_proc *proc = mm_alloc(data->mm, sizeof(struct ixfr_proc));
	if (proc == NULL) {
		return KNOT_ENOMEM;
	}
	memset(proc, 0, sizeof(struct ixfr_proc));
	gettimeofday(&proc->proc.tstamp, NULL);

	proc->changesets = changesets_create(0);
	if (proc->changesets == NULL) {
		mm_free(data->mm, proc);
		return KNOT_ENOMEM;
	}
	proc->state = IXFR_START;
	proc->zone = data->param->zone;
	proc->mm = data->mm;

	data->ext = proc;
	data->ext_cleanup = &ixfrin_cleanup;

	return KNOT_EOK;
}

/*! \brief Finalizes IXFR-in processing. */
static int ixfrin_finalize(struct answer_data *adata)
{
	struct ixfr_proc *ixfr = adata->ext;

	assert(ixfr->state == IXFR_DONE);
	int ret = zone_change_apply_and_store(&ixfr->changesets,
	                                      ixfr->zone, "IXFR", adata->mm);
	if (ret != KNOT_EOK) {
		IXFRIN_LOG(LOG_ERR, "Failed to apply changes to zone - %s",
		           knot_strerror(ret));
		return ret;
	}

	struct timeval now = {0};
	gettimeofday(&now, NULL);
	IXFRIN_LOG(LOG_INFO, "Finished in %.02fs (%u messages, ~%.01fkB).",
	           time_diff(&ixfr->proc.tstamp, &now) / 1000.0,
	           ixfr->proc.npkts, ixfr->proc.nbytes / 1024.0);

	return KNOT_EOK;
}

/*! \brief Stores starting SOA into changesets structure. */
static int solve_start(const knot_rrset_t *rr, changesets_t *changesets, mm_ctx_t *mm)
{
	assert(changesets->first_soa == NULL);
	if (rr->type != KNOT_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	// Store the first SOA for later use.
	changesets->first_soa = knot_rrset_copy(rr, mm);
	if (changesets->first_soa == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Decides what to do with a starting SOA (deletions). */
static int solve_soa_del(const knot_rrset_t *rr, changesets_t *changesets,
                         mm_ctx_t *mm)
{
	if (rr->type != KNOT_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	// Create new changeset.
	changeset_t *change = changesets_create_changeset(changesets);
	if (change == NULL) {
		return KNOT_ENOMEM;
	}

	// Store SOA into changeset.
	change->soa_from = knot_rrset_copy(rr, mm);
	if (change->soa_from == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Stores ending SOA into changeset. */
static int solve_soa_add(const knot_rrset_t *rr, changeset_t *change, mm_ctx_t *mm)
{
	assert(rr->type == KNOT_RRTYPE_SOA);
	change->soa_to= knot_rrset_copy(rr, mm);
	if (change->soa_to == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Adds single RR into given section of changeset. */
static int add_part(const knot_rrset_t *rr, changeset_t *change, int part, mm_ctx_t *mm)
{
	assert(rr->type != KNOT_RRTYPE_SOA);
	knot_rrset_t *copy = knot_rrset_copy(rr, mm);
	if (copy) {
		int ret = changeset_add_rrset(change, copy, part);
		if (ret != KNOT_EOK) {
			return ret;
		}
		return KNOT_EOK;
	} else {
		return KNOT_ENOMEM;
	}
}

/*! \brief Adds single RR into remove section of changeset. */
static int solve_del(const knot_rrset_t *rr, changeset_t *change, mm_ctx_t *mm)
{
	return add_part(rr, change, CHANGESET_REMOVE, mm);
}

/*! \brief Adds single RR into add section of changeset. */
static int solve_add(const knot_rrset_t *rr, changeset_t *change, mm_ctx_t *mm)
{
	return add_part(rr, change, CHANGESET_ADD, mm);
}

/*! \brief Decides what the next IXFR-in state should be. */
static int ixfrin_next_state(struct ixfr_proc *proc, const knot_rrset_t *rr)
{
	const bool soa = (rr->type == KNOT_RRTYPE_SOA);
	if (soa &&
	    (proc->state == IXFR_SOA_ADD || proc->state == IXFR_ADD)) {
		// Check end of transfer.
		if (knot_rrset_equal(rr, proc->changesets->first_soa,
		                     KNOT_RRSET_COMPARE_WHOLE)) {
			// Final SOA encountered, transfer done.
			return IXFR_DONE;
		}
	}

	switch (proc->state) {
	case IXFR_START:
		// Final SOA already stored or transfer start.
		return proc->changesets->first_soa ? IXFR_SOA_DEL : IXFR_START;
	case IXFR_SOA_DEL:
		// Empty delete section or start of delete section.
		return soa ? IXFR_SOA_ADD : IXFR_DEL;
	case IXFR_SOA_ADD:
		// Empty add section or start of add section.
		return soa ? IXFR_SOA_DEL : IXFR_ADD;
	case IXFR_DEL:
		// End of delete section or continue.
		return soa ? IXFR_SOA_ADD : IXFR_DEL;
	case IXFR_ADD:
		// End of add section or continue.
		return soa ? IXFR_SOA_DEL : IXFR_ADD;
	default:
		assert(0);
		return 0;
	}
}

/*!
 * \brief Processes single RR according to current IXFR-in state. The states
 *        correspond with IXFR-in message structure, in the order they are
 *        mentioned in the code.
 *
 * \param rr    RR to process.
 * \param proc  Processing context.
 *
 * \return KNOT_E*
 */
static int ixfrin_step(const knot_rrset_t *rr, struct ixfr_proc *proc)
{
	proc->state = ixfrin_next_state(proc, rr);
	changeset_t *change = changesets_get_last(proc->changesets);

	switch (proc->state) {
	case IXFR_START:
		return solve_start(rr, proc->changesets, proc->mm);
	case IXFR_SOA_DEL:
		return solve_soa_del(rr, proc->changesets, proc->mm);
	case IXFR_DEL:
		return solve_del(rr, change, proc->mm);
	case IXFR_SOA_ADD:
		return solve_soa_add(rr, change, proc->mm);
	case IXFR_ADD:
		return solve_add(rr, change, proc->mm);
	case IXFR_DONE:
		return KNOT_EOK;
	default:
		return KNOT_ERROR;
	}
}

/*! \brief Checks whether journal node limit has not been exceeded. */
static bool journal_limit_exceeded(struct ixfr_proc *proc)
{
	return proc->changesets->count > JOURNAL_NCOUNT;
}

/*! \brief Checks whether RR belongs into zone. */
static bool out_of_zone(const knot_rrset_t *rr, struct ixfr_proc *proc)
{
	return !knot_dname_is_sub(rr->owner, proc->zone->name) &&
	       !knot_dname_is_equal(rr->owner, proc->zone->name);
}

/*!
 * \brief Processes IXFR reply packet and fills in the changesets structure.
 *
 * \param pkt    Packet containing the IXFR reply in wire format.
 * \param adata  Answer data, including processing context.
 *
 * \return NS_PROC_MORE, NS_PROC_DONE, NS_PROC_FAIL
 */
static int process_ixfrin_packet(knot_pkt_t *pkt, struct answer_data *adata)
{
	struct ixfr_proc *ixfr = (struct ixfr_proc *)adata->ext;
	// Update counters.
	ixfr->proc.npkts  += 1;
	ixfr->proc.nbytes += pkt->size;

	// Process RRs in the message.
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	for (uint16_t i = 0; i < answer->count; ++i) {
		if (journal_limit_exceeded(ixfr)) {
			IXFRIN_LOG(LOG_WARNING, "Journal is full.");
			return NS_PROC_FAIL;
		}

		const knot_rrset_t *rr = &answer->rr[i];
		if (out_of_zone(rr, ixfr)) {
			continue;
		}

		int ret = ixfrin_step(rr, ixfr);
		if (ret != KNOT_EOK) {
			IXFRIN_LOG(LOG_ERR, "Failed - %s", knot_strerror(ret));
			return NS_PROC_FAIL;
		}

		if (ixfr->state == IXFR_DONE) {
			// Transfer done, do not consume more RRs.
			return NS_PROC_DONE;
		}
	}

	return NS_PROC_MORE;
}

/* --------------------------------- API ------------------------------------ */

int ixfr_query(knot_pkt_t *pkt, struct query_data *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return NS_PROC_FAIL;
	}

	int ret = KNOT_EOK;
	struct timeval now = {0};
	struct ixfr_proc *ixfr = (struct ixfr_proc*)qdata->ext;
	knot_pkt_t *query = qdata->query;

	/* If IXFR is disabled, respond with SOA. */
	if (qdata->param->proc_flags & NS_QUERY_NO_IXFR) {
		return ixfr_answer_soa(pkt, qdata);
	}

	/* Initialize on first call. */
	if (qdata->ext == NULL) {
		ret = ixfr_answer_init(qdata);
		switch(ret) {
		case KNOT_EOK:      /* OK */
			ixfr = (struct ixfr_proc*)qdata->ext;
			IXFROUT_LOG(LOG_INFO, "Started (serial %u -> %u).",
			            knot_soa_serial(&ixfr->soa_from->rrs),
			            knot_soa_serial(&ixfr->soa_to->rrs));
			break;
		case KNOT_EUPTODATE: /* Our zone is same age/older, send SOA. */
			IXFROUT_LOG(LOG_INFO, "Zone is up-to-date.");
			return ixfr_answer_soa(pkt, qdata);
		case KNOT_ERANGE:   /* No history -> AXFR. */
		case KNOT_ENOENT:
			IXFROUT_LOG(LOG_INFO, "Incomplete history, fallback to AXFR.");
			knot_pkt_clear(pkt);
			knot_pkt_put_question(pkt, knot_pkt_qname(query),
			                      knot_pkt_qclass(query),
			                      KNOT_RRTYPE_AXFR);
			qdata->packet_type = KNOT_QUERY_AXFR; /* Solve as AXFR. */
			return axfr_query_process(pkt, qdata);
		default:            /* Server errors. */
			IXFROUT_LOG(LOG_ERR, "Failed to start (%s).", knot_strerror(ret));
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
		IXFROUT_LOG(LOG_INFO, "Finished in %.02fs (%u messages, ~%.01fkB).",
		            time_diff(&ixfr->proc.tstamp, &now) / 1000.0,
		            ixfr->proc.npkts, ixfr->proc.nbytes / 1024.0);
		ret = NS_PROC_DONE;
		break;
	default:          /* Generic error. */
		IXFROUT_LOG(LOG_ERR, "%s", knot_strerror(ret));
		ret = NS_PROC_FAIL;
		break;
	}

	return ret;
}

int ixfr_process_answer(knot_pkt_t *pkt, struct answer_data *adata)
{
	if (pkt == NULL || adata == NULL) {
		return NS_PROC_FAIL;
	}

	/* Check RCODE. */
	uint8_t rcode = knot_wire_get_rcode(pkt->wire);
	if (rcode != KNOT_RCODE_NOERROR) {
		knot_lookup_table_t *lut = knot_lookup_by_id(knot_rcode_names, rcode);
		if (lut != NULL) {
			IXFRIN_LOG(LOG_ERR, "Server responded with %s.", lut->name);
		}
		return NS_PROC_FAIL;
	}

	/* Initialize processing with first packet. */
	if (adata->ext == NULL) {
		NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 0);
		if (!zone_transfer_needed(adata->param->zone, pkt)) {
			IXFRIN_LOG(LOG_INFO, "Server has newer zone.");
			return NS_PROC_DONE;
		}

		IXFRIN_LOG(LOG_INFO, "Starting.");
		// First packet with IXFR, init context
		int ret = ixfrin_answer_init(adata);
		if (ret != KNOT_EOK) {
			IXFRIN_LOG(LOG_ERR, "%s", knot_strerror(ret));
			return NS_PROC_FAIL;
		}
	} else {
		NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 100);
	}

	int ret = process_ixfrin_packet(pkt, adata);
	if (ret == NS_PROC_DONE) {
		NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 0);
		int fret = ixfrin_finalize(adata);
		if (fret != KNOT_EOK) {
			ret = NS_PROC_FAIL;
		}
	}

	return ret;
}

#undef IXFROUT_LOG
