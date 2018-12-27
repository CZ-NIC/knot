/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <urcu.h>

#include "contrib/mempattern.h"
#include "contrib/sockaddr.h"
#include "knot/journal/journal_metadata.h"
#include "knot/nameserver/axfr.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/ixfr.h"
#include "knot/nameserver/log.h"
#include "knot/nameserver/xfr.h"
#include "knot/zone/serial.h"
#include "libknot/libknot.h"

#define ZONE_NAME(qdata) knot_pkt_qname((qdata)->query)
#define REMOTE(qdata) (struct sockaddr *)(qdata)->params->remote

#define IXFROUT_LOG(priority, qdata, fmt...) \
	ns_log(priority, ZONE_NAME(qdata), LOG_OPERATION_IXFR, \
	       LOG_DIRECTION_OUT, REMOTE(qdata), fmt)

/*! \brief Helper macro for putting RRs into packet. */
#define IXFR_SAFE_PUT(pkt, rr) \
	int ret = knot_pkt_put((pkt), 0, (rr), KNOT_PF_NOTRUNC | KNOT_PF_ORIGTTL); \
	if (ret != KNOT_EOK) { \
		return ret; \
	}

/*! \brief Puts current RR into packet, stores state for retries. */
static int ixfr_put_chg_part(knot_pkt_t *pkt, struct ixfr_proc *ixfr,
                             journal_read_t *read)
{
	assert(pkt);
	assert(ixfr);
	assert(read);

	if (!knot_rrset_empty(&ixfr->cur_rr)) {
		IXFR_SAFE_PUT(pkt, &ixfr->cur_rr);
		journal_read_clear_rrset(&ixfr->cur_rr);
	}

	while (journal_read_rrset(read, &ixfr->cur_rr, true)) {
		IXFR_SAFE_PUT(pkt, &ixfr->cur_rr);
		knot_rrset_clear(&ixfr->cur_rr, NULL);
	}

	return journal_read_get_error(read, KNOT_EOK);
}

/*!
 * \brief Process the changes from journal.
 * \note Keep in mind that this function must be able to resume processing,
 *       for example if it fills a packet and returns ESPACE, it is called again
 *       with next empty answer and it must resume the processing exactly where
 *       it's left off.
 */
static int ixfr_process_journal(knot_pkt_t *pkt, const void *item,
                                struct xfr_proc *xfer)
{
	int ret = KNOT_EOK;
	struct ixfr_proc *ixfr = (struct ixfr_proc *)xfer;
	journal_read_t *read = (journal_read_t *)item;

	ret = ixfr_put_chg_part(pkt, ixfr, read);

	return ret;
}

#undef IXFR_SAFE_PUT

static int ixfr_load_chsets(journal_read_t **journal_read, zone_t *zone,
                            const knot_rrset_t *their_soa)
{
	assert(journal_read);
	assert(zone);

	/* Compare serials. */
	uint32_t serial_to = zone_contents_serial(zone->contents), j_serial_to;
	uint32_t serial_from = knot_soa_serial(their_soa->rrs.rdata);
	if (serial_compare(serial_to, serial_from) & SERIAL_MASK_LEQ) { /* We have older/same age zone. */
		return KNOT_EUPTODATE;
	}

	zone_journal_t j = zone_journal(zone);
	bool j_exists = false;
	int ret = journal_info(j, &j_exists, NULL, &j_serial_to, NULL, NULL, NULL, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	} else if (!j_exists) {
		return KNOT_ENOENT;
	} else if (j_serial_to != serial_to) {
		return KNOT_ERROR;
	}

	return journal_read_begin(zone_journal(zone), false, serial_from, journal_read);
}

static int ixfr_query_check(knotd_qdata_t *qdata)
{
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);
	NS_NEED_AUTH(qdata, ACL_ACTION_TRANSFER);
	NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL);

	/* Need SOA authority record. */
	const knot_pktsection_t *authority = knot_pkt_section(qdata->query, KNOT_AUTHORITY);
	const knot_rrset_t *their_soa = knot_pkt_rr(authority, 0);
	if (authority->count < 1 || their_soa->type != KNOT_RRTYPE_SOA) {
		qdata->rcode = KNOT_RCODE_FORMERR;
		return KNOT_STATE_FAIL;
	}
	/* SOA needs to match QNAME. */
	NS_NEED_QNAME(qdata, their_soa->owner, KNOT_RCODE_FORMERR);

	return KNOT_STATE_DONE;
}

static void ixfr_answer_cleanup(knotd_qdata_t *qdata)
{
	struct ixfr_proc *ixfr = (struct ixfr_proc *)qdata->extra->ext;
	knot_mm_t *mm = qdata->mm;

	ptrlist_free(&ixfr->proc.nodes, mm);
	journal_read_end(ixfr->journal_ctx);
	mm_free(mm, qdata->extra->ext);

	/* Allow zone changes (finished). */
	rcu_read_unlock();
}

static int ixfr_answer_init(knotd_qdata_t *qdata)
{
	assert(qdata);

	if (ixfr_query_check(qdata) == KNOT_STATE_FAIL) {
		if (qdata->rcode == KNOT_RCODE_FORMERR) {
			return KNOT_EMALF;
		} else {
			return KNOT_EDENIED;
		}
	}

	const knot_pktsection_t *authority = knot_pkt_section(qdata->query, KNOT_AUTHORITY);
	const knot_rrset_t *their_soa = knot_pkt_rr(authority, 0);

	knot_mm_t *mm = qdata->mm;
	struct ixfr_proc *xfer = mm_alloc(mm, sizeof(struct ixfr_proc));
	if (xfer == NULL) {
		return KNOT_ENOMEM;
	}
	memset(xfer, 0, sizeof(struct ixfr_proc));

	int ret = ixfr_load_chsets(&xfer->journal_ctx, (zone_t *)qdata->extra->zone, their_soa);
	if (ret != KNOT_EOK) {
		mm_free(mm, xfer);
		return ret;
	}

	xfr_stats_begin(&xfer->proc.stats);
	xfer->state = IXFR_SOA_DEL;
	init_list(&xfer->proc.nodes);
	knot_rrset_init_empty(&xfer->cur_rr);
	xfer->qdata = qdata;

	ptrlist_add(&xfer->proc.nodes, xfer->journal_ctx, mm);

	xfer->soa_from = knot_soa_serial(their_soa->rrs.rdata);
	xfer->soa_to = zone_contents_serial(qdata->extra->zone->contents);

	qdata->extra->ext = xfer;
	qdata->extra->ext_cleanup = &ixfr_answer_cleanup;

	/* No zone changes during multipacket answer (unlocked in ixfr_answer_cleanup) */
	rcu_read_lock();

	return KNOT_EOK;
}

static int ixfr_answer_soa(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	assert(pkt);
	assert(qdata);

	/* Check query. */
	int state = ixfr_query_check(qdata);
	if (state == KNOT_STATE_FAIL) {
		return state; /* Malformed query. */
	}

	/* Reserve space for TSIG. */
	int ret = knot_pkt_reserve(pkt, knot_tsig_wire_size(&qdata->sign.tsig_key));
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	/* Guaranteed to have zone contents. */
	const zone_node_t *apex = qdata->extra->zone->contents->apex;
	knot_rrset_t soa_rr = node_rrset(apex, KNOT_RRTYPE_SOA);
	if (knot_rrset_empty(&soa_rr)) {
		return KNOT_STATE_FAIL;
	}
	ret = knot_pkt_put(pkt, 0, &soa_rr, 0);
	if (ret != KNOT_EOK) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return KNOT_STATE_FAIL;
	}

	return KNOT_STATE_DONE;
}

int ixfr_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* If IXFR is disabled, respond with SOA. */
	if (qdata->params->flags & KNOTD_QUERY_FLAG_NO_IXFR) {
		return ixfr_answer_soa(pkt, qdata);
	}

	/* Initialize on first call. */
	struct ixfr_proc *ixfr = qdata->extra->ext;
	if (ixfr == NULL) {
		int ret = ixfr_answer_init(qdata);
		ixfr = qdata->extra->ext;
		switch (ret) {
		case KNOT_EOK:       /* OK */
			IXFROUT_LOG(LOG_INFO, qdata, "started, serial %u -> %u",
				    ixfr->soa_from, ixfr->soa_to);
			break;
		case KNOT_EUPTODATE: /* Our zone is same age/older, send SOA. */
			IXFROUT_LOG(LOG_INFO, qdata, "zone is up-to-date");
			return ixfr_answer_soa(pkt, qdata);
		case KNOT_ERANGE:    /* No history -> AXFR. */
		case KNOT_ENOENT:
			IXFROUT_LOG(LOG_INFO, qdata, "incomplete history, fallback to AXFR");
			qdata->type = KNOTD_QUERY_TYPE_AXFR; /* Solve as AXFR. */
			return axfr_process_query(pkt, qdata);
		case KNOT_EDENIED:  /* Not authorized, already logged. */
			return KNOT_STATE_FAIL;
		case KNOT_EMALF:    /* Malformed query. */
			IXFROUT_LOG(LOG_DEBUG, qdata, "malformed query");
			return KNOT_STATE_FAIL;
		default:             /* Server errors. */
			IXFROUT_LOG(LOG_ERR, qdata, "failed to start (%s)",
			            knot_strerror(ret));
			return KNOT_STATE_FAIL;
		}
	}

	/* Reserve space for TSIG. */
	int ret = knot_pkt_reserve(pkt, knot_tsig_wire_size(&qdata->sign.tsig_key));
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	/* Answer current packet (or continue). */
	ret = xfr_process_list(pkt, &ixfr_process_journal, qdata);
	switch (ret) {
	case KNOT_ESPACE: /* Couldn't write more, send packet and continue. */
		return KNOT_STATE_PRODUCE; /* Check for more. */
	case KNOT_EOK:    /* Last response. */
		xfr_stats_end(&ixfr->proc.stats);
		xfr_log_finished(ZONE_NAME(qdata), LOG_OPERATION_IXFR, LOG_DIRECTION_OUT,
		                 REMOTE(qdata), &ixfr->proc.stats);
		return KNOT_STATE_DONE;
	default:          /* Generic error. */
		IXFROUT_LOG(LOG_ERR, qdata, "failed (%s)", knot_strerror(ret));
		return KNOT_STATE_FAIL;
	}
}
