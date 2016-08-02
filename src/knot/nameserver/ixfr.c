/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <urcu.h>

#include "knot/common/log.h"
#include "knot/nameserver/axfr.h"
#include "knot/nameserver/ixfr.h"
#include "knot/nameserver/internet.h"
#include "knot/updates/apply.h"
#include "knot/zone/serial.h"
#include "knot/zone/semantic-check.h"
#include "knot/zone/zonefile.h"
#include "libknot/libknot.h"
#include "contrib/mempattern.h"
#include "contrib/print.h"
#include "contrib/sockaddr.h"

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
	changeset_iter_t cur;          /* Current changeset iteration state.*/
	knot_rrset_t cur_rr;           /* Currently processed RRSet. */
	int state;                     /* IXFR-in state. */
	knot_rrset_t *final_soa;       /* First SOA received via IXFR. */
	list_t changesets;             /* Processed changesets. */
	size_t change_count;           /* Count of changesets received. */
	size_t change_size;            /* Size of records to add and remove */
	zone_t *zone;                  /* Modified zone - for journal access. */
	knot_mm_t *mm;                 /* Memory context for RR allocations. */
	struct query_data *qdata;
	const knot_rrset_t *soa_from;
	const knot_rrset_t *soa_to;
};

/*! \brief Helper macro for putting RRs into packet. */
#define IXFR_SAFE_PUT(pkt, rr) \
	ret = knot_pkt_put((pkt), 0, (rr), KNOT_PF_NOTRUNC); \
	if (ret != KNOT_EOK) { \
		return ret; \
	}

/*! \brief Puts current RR into packet, stores state for retries. */
static int ixfr_put_chg_part(knot_pkt_t *pkt, struct ixfr_proc *ixfr,
                             changeset_iter_t *itt)
{
	assert(pkt);
	assert(ixfr);
	assert(itt);

	if (knot_rrset_empty(&ixfr->cur_rr)) {
		ixfr->cur_rr = changeset_iter_next(itt);
	}
	int ret = KNOT_EOK; // Declaration for IXFR_SAFE_PUT macro
	while(!knot_rrset_empty(&ixfr->cur_rr)) {
		IXFR_SAFE_PUT(pkt, &ixfr->cur_rr);
		ixfr->cur_rr = changeset_iter_next(itt);
	}

	return ret;
}

/*! \brief Tests if iteration has started. */
static bool iter_empty(struct ixfr_proc *ixfr)
{
	return EMPTY_LIST(ixfr->cur.iters) && knot_rrset_empty(&ixfr->cur_rr);
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
		ixfr->state = IXFR_DEL;
	}

	/* Put REMOVE RRSets. */
	if (ixfr->state == IXFR_DEL) {
		if (iter_empty(ixfr)) {
			ret = changeset_iter_rem(&ixfr->cur, chgset, false);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
		ret = ixfr_put_chg_part(pkt, ixfr, &ixfr->cur);
		if (ret != KNOT_EOK) {
			return ret;
		}
		changeset_iter_clear(&ixfr->cur);
		ixfr->state = IXFR_SOA_ADD;
	}

	/* Put next SOA. */
	if (ixfr->state == IXFR_SOA_ADD) {
		IXFR_SAFE_PUT(pkt, chgset->soa_to);
		ixfr->state = IXFR_ADD;
	}

	/* Put Add RRSets. */
	if (ixfr->state == IXFR_ADD) {
		if (iter_empty(ixfr)) {
			ret = changeset_iter_add(&ixfr->cur, chgset, false);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
		ret = ixfr_put_chg_part(pkt, ixfr, &ixfr->cur);
		if (ret != KNOT_EOK) {
			return ret;
		}
		changeset_iter_clear(&ixfr->cur);
		ixfr->state = IXFR_SOA_DEL;
	}

	/* Finished change set. */
	struct query_data *qdata = ixfr->qdata; /*< Required for IXFROUT_LOG() */
	const uint32_t serial_from = knot_soa_serial(&chgset->soa_from->rrs);
	const uint32_t serial_to = knot_soa_serial(&chgset->soa_to->rrs);
	IXFROUT_LOG(LOG_DEBUG, "serial %u -> %u", serial_from, serial_to);

	return ret;
}

#undef IXFR_SAFE_PUT

/*! \brief Loads IXFRs from journal. */
static int ixfr_load_chsets(list_t *chgsets, const zone_t *zone,
                            const knot_rrset_t *their_soa)
{
	assert(chgsets);
	assert(zone);

	/* Compare serials. */
	uint32_t serial_to = zone_contents_serial(zone->contents);
	uint32_t serial_from = knot_soa_serial(&their_soa->rrs);
	int ret = serial_compare(serial_to, serial_from);
	if (ret <= 0) { /* We have older/same age zone. */
		return KNOT_EUPTODATE;
	}

	char *path = conf_journalfile(conf(), zone->name);
	pthread_mutex_lock((pthread_mutex_t *)&zone->journal_lock);
	ret = journal_load_changesets(path, zone, chgsets, serial_from, serial_to);
	pthread_mutex_unlock((pthread_mutex_t *)&zone->journal_lock);
	free(path);

	if (ret != KNOT_EOK) {
		changesets_free(chgsets);
	}

	return ret;
}

/*! \brief Check IXFR query validity. */
static int ixfr_query_check(struct query_data *qdata)
{
	/* Check if zone exists. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);

	/* Need IXFR query type. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_IXFR, KNOT_RCODE_FORMERR);
	/* Need SOA authority record. */
	const knot_pktsection_t *authority = knot_pkt_section(qdata->query, KNOT_AUTHORITY);
	const knot_rrset_t *their_soa = knot_pkt_rr(authority, 0);
	if (authority->count < 1 || their_soa->type != KNOT_RRTYPE_SOA) {
		qdata->rcode = KNOT_RCODE_FORMERR;
		return KNOT_STATE_FAIL;
	}
	/* SOA needs to match QNAME. */
	NS_NEED_QNAME(qdata, their_soa->owner, KNOT_RCODE_FORMERR);

	/* Check transcation security and zone contents. */
	NS_NEED_AUTH(qdata, qdata->zone->name, ACL_ACTION_TRANSFER);
	NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL); /* Check expiration. */

	return KNOT_STATE_DONE;
}

/*! \brief Cleans up ixfr processing context. */
static void ixfr_answer_cleanup(struct query_data *qdata)
{
	struct ixfr_proc *ixfr = (struct ixfr_proc *)qdata->ext;
	knot_mm_t *mm = qdata->mm;

	ptrlist_free(&ixfr->proc.nodes, mm);
	changeset_iter_clear(&ixfr->cur);
	changesets_free(&ixfr->changesets);
	mm_free(mm, qdata->ext);

	/* Allow zone changes (finished). */
	rcu_read_unlock();
}

/*! \brief Inits ixfr processing context. */
static int ixfr_answer_init(struct query_data *qdata)
{
	/* Check IXFR query validity. */
	int state = ixfr_query_check(qdata);
	if (state == KNOT_STATE_FAIL) {
		if (qdata->rcode == KNOT_RCODE_FORMERR) {
			return KNOT_EMALF;
		} else {
			return KNOT_EDENIED;
		}
	}

	/* Compare serials. */
	const knot_pktsection_t *authority = knot_pkt_section(qdata->query, KNOT_AUTHORITY);
	const knot_rrset_t *their_soa = knot_pkt_rr(authority, 0);
	list_t chgsets;
	init_list(&chgsets);
	int ret = ixfr_load_chsets(&chgsets, (zone_t *)qdata->zone, their_soa);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Initialize transfer processing. */
	knot_mm_t *mm = qdata->mm;
	struct ixfr_proc *xfer = mm_alloc(mm, sizeof(struct ixfr_proc));
	if (xfer == NULL) {
		changesets_free(&chgsets);
		return KNOT_ENOMEM;
	}
	memset(xfer, 0, sizeof(struct ixfr_proc));
	gettimeofday(&xfer->proc.tstamp, NULL);
	xfer->state = IXFR_SOA_DEL;
	init_list(&xfer->proc.nodes);
	init_list(&xfer->changesets);
	init_list(&xfer->cur.iters);
	knot_rrset_init_empty(&xfer->cur_rr);
	add_tail_list(&xfer->changesets, &chgsets);
	xfer->qdata = qdata;

	/* Put all changesets to processing queue. */
	changeset_t *chs = NULL;
	WALK_LIST(chs, xfer->changesets) {
		ptrlist_add(&xfer->proc.nodes, chs, mm);
	}

	/* Keep first and last serial. */
	chs = HEAD(xfer->changesets);
	xfer->soa_from = chs->soa_from;
	chs = TAIL(xfer->changesets);
	xfer->soa_to = chs->soa_to;

	/* Set up cleanup callback. */
	qdata->ext = xfer;
	qdata->ext_cleanup = &ixfr_answer_cleanup;

	/* No zone changes during multipacket answer (unlocked in axfr_answer_cleanup) */
	rcu_read_lock();

	return KNOT_EOK;
}

/*! \brief Sends response to SOA query. */
static int ixfr_answer_soa(knot_pkt_t *pkt, struct query_data *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* Check query. */
	int state = ixfr_query_check(qdata);
	if (state == KNOT_STATE_FAIL) {
		return state; /* Malformed query. */
	}

	/* Reserve space for TSIG. */
	knot_pkt_reserve(pkt, knot_tsig_wire_maxsize(&qdata->sign.tsig_key));

	/* Guaranteed to have zone contents. */
	const zone_node_t *apex = qdata->zone->contents->apex;
	knot_rrset_t soa_rr = node_rrset(apex, KNOT_RRTYPE_SOA);
	if (knot_rrset_empty(&soa_rr)) {
		return KNOT_STATE_FAIL;
	}
	int ret = knot_pkt_put(pkt, 0, &soa_rr, 0);
	if (ret != KNOT_EOK) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return KNOT_STATE_FAIL;
	}

	return KNOT_STATE_DONE;
}

/* ------------------------- IXFR-in processing ----------------------------- */

/*! \brief Checks whether server responded with AXFR-style IXFR. */
static bool ixfr_is_axfr(const knot_pkt_t *pkt)
{
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	return answer->count >= 2 &&
	       knot_pkt_rr(answer, 0)->type == KNOT_RRTYPE_SOA &&
	       knot_pkt_rr(answer, 1)->type != KNOT_RRTYPE_SOA;
}

/*! \brief Cleans up data allocated by IXFR-in processing. */
static void ixfrin_cleanup(struct answer_data *data)
{
	struct ixfr_proc *proc = data->ext;
	if (proc) {
		changesets_free(&proc->changesets);
		knot_rrset_free(&proc->final_soa, proc->mm);
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

	init_list(&proc->changesets);

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

	apply_ctx_t a_ctx = { { 0 } };
	apply_init_ctx(&a_ctx, APPLY_STRICT);

	zone_contents_t *new_contents;
	int ret = apply_changesets(&a_ctx, ixfr->zone, &ixfr->changesets, &new_contents);
	if (ret != KNOT_EOK) {
		IXFRIN_LOG(LOG_WARNING, "failed to apply changes to zone (%s)",
		           knot_strerror(ret));
		return ret;
	}

	err_handler_logger_t handler;
	handler._cb.cb = err_handler_logger;
	ret = zone_do_sem_checks(new_contents, false, &handler._cb);

	if (ret != KNOT_EOK) {
		IXFRIN_LOG(LOG_WARNING, "failed to apply changes to zone (%s)",
		           knot_strerror(ret));
		update_rollback(&a_ctx);
		update_free_zone(&new_contents);
		return ret;
	}

	conf_val_t val = conf_zone_get(adata->param->conf, C_MAX_ZONE_SIZE,
	                               ixfr->zone->name);
	const int64_t size_limit = conf_int(&val);

	if (new_contents->size > size_limit) {
		IXFRIN_LOG(LOG_WARNING, "zone size exceeded");
		update_rollback(&a_ctx);
		update_free_zone(&new_contents);
		return KNOT_EZONESIZE;
	}

	/* Write changes to journal. */
	ret = zone_changes_store(adata->param->conf, ixfr->zone, &ixfr->changesets);
	if (ret != KNOT_EOK) {
		IXFRIN_LOG(LOG_WARNING, "failed to write changes to journal (%s)",
		           knot_strerror(ret));
		update_rollback(&a_ctx);
		update_free_zone(&new_contents);
		return ret;
	}

	/* Switch zone contents. */
	zone_contents_t *old_contents = zone_switch_contents(ixfr->zone, new_contents);
	ixfr->zone->flags &= ~ZONE_EXPIRED;
	synchronize_rcu();

	struct timeval now = {0};
	gettimeofday(&now, NULL);
	IXFRIN_LOG(LOG_INFO, "finished, "
	           "serial %u -> %u, %.02f seconds, %u messages, %u bytes",
	           zone_contents_serial(old_contents),
	           zone_contents_serial(new_contents),
	           time_diff(&ixfr->proc.tstamp, &now) / 1000.0,
	           ixfr->proc.npkts, ixfr->proc.nbytes);

	update_free_zone(&old_contents);
	update_cleanup(&a_ctx);

	return KNOT_EOK;
}

/*! \brief Stores starting SOA into changesets structure. */
static int solve_start(const knot_rrset_t *rr, struct ixfr_proc *proc)
{
	assert(proc->final_soa == NULL);
	if (rr->type != KNOT_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	// Store the first SOA for later use.
	proc->final_soa = knot_rrset_copy(rr, proc->mm);
	if (proc->final_soa == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Decides what to do with a starting SOA (deletions). */
static int solve_soa_del(const knot_rrset_t *rr, struct ixfr_proc *proc)
{
	if (rr->type != KNOT_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	// Create new changeset.
	changeset_t *change = changeset_new(proc->zone->name);
	if (change == NULL) {
		return KNOT_ENOMEM;
	}

	// Store SOA into changeset.
	change->soa_from = knot_rrset_copy(rr, NULL);
	if (change->soa_from == NULL) {
		changeset_clear(change);
		return KNOT_ENOMEM;
	}

	// Add changeset.
	add_tail(&proc->changesets, &change->n);
	++proc->change_count;

	return KNOT_EOK;
}

/*! \brief Stores ending SOA into changeset. */
static int solve_soa_add(const knot_rrset_t *rr, changeset_t *change, knot_mm_t *mm)
{
	assert(rr->type == KNOT_RRTYPE_SOA);
	change->soa_to = knot_rrset_copy(rr, NULL);
	if (change->soa_to == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Adds single RR into remove section of changeset. */
static int solve_del(const knot_rrset_t *rr, changeset_t *change, knot_mm_t *mm)
{
	return changeset_rem_rrset(change, rr, 0);
}

/*! \brief Adds single RR into add section of changeset. */
static int solve_add(const knot_rrset_t *rr, changeset_t *change, knot_mm_t *mm)
{
	return changeset_add_rrset(change, rr, 0);
}

/*! \brief Decides what the next IXFR-in state should be. */
static int ixfrin_next_state(struct ixfr_proc *proc, const knot_rrset_t *rr)
{
	const bool soa = (rr->type == KNOT_RRTYPE_SOA);
	if (soa &&
	    (proc->state == IXFR_SOA_ADD || proc->state == IXFR_ADD)) {
		// Check end of transfer.
		if (knot_rrset_equal(rr, proc->final_soa,
		                     KNOT_RRSET_COMPARE_WHOLE)) {
			// Final SOA encountered, transfer done.
			return IXFR_DONE;
		}
	}

	switch (proc->state) {
	case IXFR_START:
		// Final SOA already stored or transfer start.
		return proc->final_soa ? IXFR_SOA_DEL : IXFR_START;
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
	changeset_t *change = TAIL(proc->changesets);

	int ret;
	switch (proc->state) {
	case IXFR_START:
		return solve_start(rr, proc);
	case IXFR_SOA_DEL:
		ret = solve_soa_del(rr, proc);
		break;
	case IXFR_DEL:
		ret = solve_del(rr, change, proc->mm);
		break;
	case IXFR_SOA_ADD:
		ret = solve_soa_add(rr, change, proc->mm);
		break;
	case IXFR_ADD:
		ret = solve_add(rr, change, proc->mm);
		break;
	case IXFR_DONE:
		return KNOT_EOK;
	default:
		return KNOT_ERROR;
	}
	if (ret == KNOT_EOK) {
		proc->change_size += knot_rrset_size(rr);
	}
	return ret;
}

/*! \brief Checks whether journal node limit has not been exceeded. */
static bool journal_limit_exceeded(struct ixfr_proc *proc)
{
	return proc->change_count > JOURNAL_NCOUNT;
}

/*! \brief Checks whether RR belongs into zone. */
static bool out_of_zone(const knot_rrset_t *rr, struct ixfr_proc *proc)
{
	return !knot_dname_in(proc->zone->name, rr->owner);
}

/*!
 * \brief Processes IXFR reply packet and fills in the changesets structure.
 *
 * \param pkt    Packet containing the IXFR reply in wire format.
 * \param adata  Answer data, including processing context.
 *
 * \return KNOT_STATE_CONSUME, KNOT_STATE_DONE, KNOT_STATE_FAIL
 */
static int process_ixfrin_packet(knot_pkt_t *pkt, struct answer_data *adata)
{
	struct ixfr_proc *ixfr = (struct ixfr_proc *)adata->ext;

	// Update counters.
	ixfr->proc.npkts  += 1;
	ixfr->proc.nbytes += pkt->size;

	conf_val_t val = conf_zone_get(adata->param->conf, C_MAX_ZONE_SIZE,
	                               ixfr->zone->name);
	const int64_t size_limit = conf_int(&val);

	// Process RRs in the message.
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	for (uint16_t i = 0; i < answer->count; ++i) {
		if (journal_limit_exceeded(ixfr)) {
			IXFRIN_LOG(LOG_WARNING, "journal is full");
			return KNOT_STATE_FAIL;
		}

		const knot_rrset_t *rr = knot_pkt_rr(answer, i);
		if (out_of_zone(rr, ixfr)) {
			continue;
		}

		int ret = ixfrin_step(rr, ixfr);
		if (ret != KNOT_EOK) {
			IXFRIN_LOG(LOG_WARNING, "failed (%s)", knot_strerror(ret));
			return KNOT_STATE_FAIL;
		}

		if (ixfr->state == IXFR_DONE) {
			// Transfer done, do not consume more RRs.
			return KNOT_STATE_DONE;
		}

		if (ixfr->change_size > 2 * size_limit) {
			IXFRIN_LOG(LOG_WARNING, "transfer size exceeded");
		}

	}

	return KNOT_STATE_CONSUME;
}

/* --------------------------------- API ------------------------------------ */

int ixfr_process_query(knot_pkt_t *pkt, struct query_data *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return KNOT_STATE_FAIL;
	}

	int ret = KNOT_EOK;
	struct timeval now = {0};
	struct ixfr_proc *ixfr = (struct ixfr_proc*)qdata->ext;

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
			IXFROUT_LOG(LOG_INFO, "started, serial %u -> %u",
			            knot_soa_serial(&ixfr->soa_from->rrs),
			            knot_soa_serial(&ixfr->soa_to->rrs));
			break;
		case KNOT_EUPTODATE: /* Our zone is same age/older, send SOA. */
			IXFROUT_LOG(LOG_INFO, "zone is up-to-date");
			return ixfr_answer_soa(pkt, qdata);
		case KNOT_ERANGE:   /* No history -> AXFR. */
		case KNOT_ENOENT:
			IXFROUT_LOG(LOG_INFO, "incomplete history, fallback to AXFR");
			qdata->packet_type = KNOT_QUERY_AXFR; /* Solve as AXFR. */
			return axfr_process_query(pkt, qdata);
		default:            /* Server errors. */
			IXFROUT_LOG(LOG_ERR, "failed to start (%s)", knot_strerror(ret));
			return KNOT_STATE_FAIL;
		}
	}

	/* Reserve space for TSIG. */
	knot_pkt_reserve(pkt, knot_tsig_wire_maxsize(&qdata->sign.tsig_key));

	/* Answer current packet (or continue). */
	ret = xfr_process_list(pkt, &ixfr_process_changeset, qdata);
	switch(ret) {
	case KNOT_ESPACE: /* Couldn't write more, send packet and continue. */
		return KNOT_STATE_PRODUCE; /* Check for more. */
	case KNOT_EOK:    /* Last response. */
		gettimeofday(&now, NULL);
		IXFROUT_LOG(LOG_INFO,
		            "finished, %.02f seconds, %u messages, %u bytes",
		            time_diff(&ixfr->proc.tstamp, &now) / 1000.0,
		            ixfr->proc.npkts, ixfr->proc.nbytes);
		ret = KNOT_STATE_DONE;
		break;
	default:          /* Generic error. */
		IXFROUT_LOG(LOG_ERR, "failed (%s)", knot_strerror(ret));
		ret = KNOT_STATE_FAIL;
		break;
	}

	return ret;
}

static int check_format(knot_pkt_t *pkt)
{
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);

	if (answer->count >= 1 && knot_pkt_rr(answer, 0)->type == KNOT_RRTYPE_SOA) {
		return KNOT_EOK;
	} else {
		return KNOT_EMALF;
	}
}

int ixfr_process_answer(knot_pkt_t *pkt, struct answer_data *adata)
{
	if (pkt == NULL || adata == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* Check RCODE. */
	uint8_t rcode = knot_wire_get_rcode(pkt->wire);
	if (rcode != KNOT_RCODE_NOERROR) {
		const knot_lookup_t *lut = knot_lookup_by_id(knot_rcode_names, rcode);
		if (lut != NULL) {
			IXFRIN_LOG(LOG_WARNING, "server responded with %s", lut->name);
		}
		return KNOT_STATE_FAIL;
	}

	if (adata->ext == NULL) {
		if (check_format(pkt) != KNOT_EOK) {
			IXFRIN_LOG(LOG_WARNING, "malformed response");
			return KNOT_STATE_FAIL;
		}

		/* Check for AXFR-style IXFR. */
		if (ixfr_is_axfr(pkt)) {
			IXFRIN_LOG(LOG_NOTICE, "receiving AXFR-style IXFR");
			adata->response_type = KNOT_RESPONSE_AXFR;
			return axfr_process_answer(pkt, adata);
		}

		/* Initialize processing with first packet. */
		NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 0);
		if (!zone_transfer_needed(adata->param->zone, pkt)) {
			if (knot_pkt_section(pkt, KNOT_ANSWER)->count > 1) {
				IXFRIN_LOG(LOG_WARNING, "old data, ignoring");
			} else {
				/* Single-SOA answer. */
				IXFRIN_LOG(LOG_INFO, "zone is up-to-date");
			}
			return KNOT_STATE_DONE;
		}

		IXFRIN_LOG(LOG_INFO, "starting");
		// First packet with IXFR, init context
		int ret = ixfrin_answer_init(adata);
		if (ret != KNOT_EOK) {
			IXFRIN_LOG(LOG_WARNING, "failed (%s)", knot_strerror(ret));
			return KNOT_STATE_FAIL;
		}
	} else {
		NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 100);
	}

	int ret = process_ixfrin_packet(pkt, adata);
	if (ret == KNOT_STATE_DONE) {
		NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 0);
		int fret = ixfrin_finalize(adata);
		if (fret != KNOT_EOK) {
			ret = KNOT_STATE_FAIL;
		}
	}

	return ret;
}
