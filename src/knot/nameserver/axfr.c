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
#include "knot/nameserver/process_answer.h"
#include "knot/updates/apply.h"
#include "knot/zone/zonefile.h"
#include "common/debug.h"
#include "common/descriptor.h"
#include "common/lists.h"

/* AXFR context. @note aliasing the generic xfr_proc */
struct axfr_proc {
	struct xfr_proc proc;
	hattrie_iter_t *i;
	unsigned cur_rrset;
};

static int put_rrsets(knot_pkt_t *pkt, zone_node_t *node, struct axfr_proc *state)
{
	int ret = KNOT_EOK;
	int i = state->cur_rrset;
	uint16_t rrset_count = node->rrset_count;
	unsigned flags = KNOT_PF_NOTRUNC;

	/* Append all RRs. */
	for (;i < rrset_count; ++i) {
		knot_rrset_t rrset = node_rrset_at(node, i);
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
	zone_node_t *node = NULL;
	while(!hattrie_iter_finished(axfr->i)) {
		node = (zone_node_t *)*hattrie_iter_val(axfr->i);
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

static void axfr_query_cleanup(struct query_data *qdata)
{
	struct axfr_proc *axfr = (struct axfr_proc *)qdata->ext;
	mm_ctx_t *mm = qdata->mm;

	ptrlist_free(&axfr->proc.nodes, mm);
	mm->free(axfr);

	/* Allow zone changes (finished). */
	rcu_read_unlock();
}

static int axfr_query_init(struct query_data *qdata)
{
	assert(qdata);

	/* Create transfer processing context. */
	mm_ctx_t *mm = qdata->mm;

	zone_contents_t *zone = qdata->zone->contents;
	struct axfr_proc *axfr = mm->alloc(mm->ctx, sizeof(struct axfr_proc));
	if (axfr == NULL) {
		return KNOT_ENOMEM;
	}
	memset(axfr, 0, sizeof(struct axfr_proc));
	init_list(&axfr->proc.nodes);

	/* Put data to process. */
	gettimeofday(&axfr->proc.tstamp, NULL);
	ptrlist_add(&axfr->proc.nodes, zone->nodes, mm);
	/* Put NSEC3 data if exists. */
	if (!knot_zone_tree_is_empty(zone->nsec3_nodes)) {
		ptrlist_add(&axfr->proc.nodes, zone->nsec3_nodes, mm);
	}

	/* Set up cleanup callback. */
	qdata->ext = axfr;
	qdata->ext_cleanup = &axfr_query_cleanup;

	/* No zone changes during multipacket answer (unlocked in axfr_answer_cleanup) */
	rcu_read_lock();

	return KNOT_EOK;
}

int xfr_process_list(knot_pkt_t *pkt, xfr_put_cb process_item, struct query_data *qdata)
{

	int ret = KNOT_EOK;
	mm_ctx_t *mm = qdata->mm;
	struct xfr_proc *xfer = qdata->ext;

	zone_contents_t *zone = qdata->zone->contents;
	knot_rrset_t soa_rr = node_rrset(zone->apex, KNOT_RRTYPE_SOA);

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
#define AXFROUT_LOG(severity, msg...) \
	QUERY_LOG(severity, qdata, "Outgoing AXFR", msg)

int axfr_query(knot_pkt_t *pkt, struct query_data *qdata)
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

		ret = axfr_query_init(qdata);
		if (ret != KNOT_EOK) {
			AXFROUT_LOG(LOG_ERR, "Failed to start (%s).", knot_strerror(ret));
			return ret;
		} else {
			AXFROUT_LOG(LOG_INFO, "Started (serial %u).", zone_contents_serial(qdata->zone->contents));
		}
	}

	/* Reserve space for TSIG. */
	knot_pkt_reserve(pkt, tsig_wire_maxsize(qdata->sign.tsig_key));

	/* Answer current packet (or continue). */
	struct axfr_proc *axfr = (struct axfr_proc *)qdata->ext;
	ret = xfr_process_list(pkt, &axfr_process_node_tree, qdata);
	switch(ret) {
	case KNOT_ESPACE: /* Couldn't write more, send packet and continue. */
		return NS_PROC_FULL; /* Check for more. */
	case KNOT_EOK:    /* Last response. */
		gettimeofday(&now, NULL);
		AXFROUT_LOG(LOG_INFO, "Finished in %.02fs (%u messages, ~%.01fkB).",
		         time_diff(&axfr->proc.tstamp, &now) / 1000.0,
		         axfr->proc.npkts, axfr->proc.nbytes / 1024.0);
		return NS_PROC_DONE;
		break;
	default:          /* Generic error. */
		AXFROUT_LOG(LOG_ERR, "%s", knot_strerror(ret));
		return NS_PROC_FAIL;
	}
}
#undef AXFR_QLOG

static void axfr_answer_cleanup(struct answer_data *data)
{
	struct xfr_proc *proc = data->ext;
	if (proc) {
		zone_contents_deep_free(&proc->contents);
		mm_free(data->mm, proc);
		data->ext = NULL;
	}
}

static int axfr_answer_init(struct answer_data *data)
{
	assert(data);

	/* Create new zone contents. */
	zone_t *zone = data->param->zone;
	zone_contents_t *new_contents = zone_contents_new(zone->name);
	if (new_contents == NULL) {
		return KNOT_ENOMEM;
	}

	/* Create new processing context. */
	struct xfr_proc *proc = mm_alloc(data->mm, sizeof(struct xfr_proc));
	if (proc == NULL) {
		zone_contents_deep_free(&new_contents);
		return KNOT_ENOMEM;
	}

	memset(proc, 0, sizeof(struct xfr_proc));
	proc->contents = new_contents;
	gettimeofday(&proc->tstamp, NULL);

	/* Set up cleanup callback. */
	data->ext = proc;
	data->ext_cleanup = &axfr_answer_cleanup;

	return KNOT_EOK;
}

/* AXFR-specific logging (internal, expects 'data' variable set). */
#define AXFRIN_LOG(severity, msg...) \
	ANSWER_LOG(severity, data, "Incoming AXFR", msg)

static int axfr_answer_finalize(struct answer_data *data)
{
	struct timeval now;
	gettimeofday(&now, NULL);

	/*
	 * Adjust zone so that node count is set properly and nodes are
	 * marked authoritative / delegation point.
	 */
	struct xfr_proc *proc = data->ext;
	int rc = zone_contents_adjust_full(proc->contents, NULL, NULL);
	if (rc != KNOT_EOK) {
		return rc;
	}

	/* Write zone file. */
	zone_t *zone = data->param->zone;
	rc = zonefile_write(zone->conf->file, proc->contents, data->param->remote);
	if (rc != KNOT_EOK) {
		return rc;
	}

	/* Switch contents. */
	zone_contents_t *old_contents = update_switch_contents(zone, proc->contents);
	AXFRIN_LOG(LOG_INFO, "Serial %u -> %u",
	           zone_contents_serial(old_contents),
	           zone_contents_serial(proc->contents));

	AXFRIN_LOG(LOG_INFO, "Finished in %.02fs (%u messages, ~%.01fkB).",
	         time_diff(&proc->tstamp, &now) / 1000.0,
	         proc->npkts, proc->nbytes / 1024.0);

	/* Do not free new contents with cleanup. */
	zone_contents_deep_free(&old_contents);
	proc->contents = NULL;

	return KNOT_EOK;
}

static int process_axfr_packet(knot_pkt_t *pkt, struct xfr_proc *proc)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	++proc->npkts;

	// Init zone creator
	zcreator_t zc = {.z = proc->contents, .master = false, .ret = KNOT_EOK };

	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	for (uint16_t i = 0; i < answer->count; ++i) {
		const knot_rrset_t *rr = &answer->rr[i];
		if (rr->type == KNOT_RRTYPE_SOA &&
		    node_rrtype_exists(zc.z->apex, KNOT_RRTYPE_SOA)) {
			// Last SOA, last message, check TSIG.
//			int ret = xfrin_check_tsig(pkt, xfr, 1);
#warning TODO: TSIG API
//			if (ret != KNOT_EOK) {
//				return ret;
//			}
			return NS_PROC_DONE;
		} else {
			int ret = zcreator_step(&zc, rr);
			if (ret != KNOT_EOK) {
				return NS_PROC_FAIL;
			}
		}
	}

	// Check possible TSIG at the end of DNS message.
//	return xfrin_check_tsig(pkt, xfr, knot_ns_tsig_required(xfr->packet_nr));
#warning TODO: TSIG API
	return NS_PROC_MORE;
}

int axfr_process_answer(knot_pkt_t *pkt, struct answer_data *data)
{
	/* Initialize processing with first packet. */
	int ret = KNOT_EOK;
	if (data->ext == NULL) {
		ret = axfr_answer_init(data);
		if (ret != KNOT_EOK) {
			return NS_PROC_FAIL;
		}
	}

	/* Process answer packet. */
	ret = process_axfr_packet(pkt, (struct xfr_proc *)data->ext);
	if (ret == NS_PROC_DONE) {
		/* This was the last packet, finalize zone and publish it. */
		ret = axfr_answer_finalize(data);
		if (ret != KNOT_EOK) {
			return NS_PROC_FAIL;
		}

		return ret;
	}

	return ret;
}

#undef AXFR_QRLOG
