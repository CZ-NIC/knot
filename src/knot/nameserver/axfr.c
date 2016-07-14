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
#include "libknot/descriptor.h"
#include "common-knot/lists.h"

/* AXFR context. @note aliasing the generic xfr_proc */
struct axfr_proc {
	struct xfr_proc proc;
	hattrie_iter_t *i;
	unsigned cur_rrset;
};

static int axfr_put_rrsets(knot_pkt_t *pkt, zone_node_t *node,
                           struct axfr_proc *state)
{
	assert(node != NULL);

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

static int axfr_process_node_tree(knot_pkt_t *pkt, const void *item,
                                  struct xfr_proc *state)
{
	assert(item != NULL);

	struct axfr_proc *axfr = (struct axfr_proc*)state;

	if (axfr->i == NULL) {
		axfr->i = hattrie_iter_begin(item, true);
	}

	/* Put responses. */
	int ret = KNOT_EOK;
	zone_node_t *node = NULL;
	while (!hattrie_iter_finished(axfr->i)) {
		node = (zone_node_t *)*hattrie_iter_val(axfr->i);
		ret = axfr_put_rrsets(pkt, node, axfr);
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

	hattrie_iter_free(axfr->i);
	ptrlist_free(&axfr->proc.nodes, qdata->mm);
	mm_free(qdata->mm, axfr);

	/* Allow zone changes (finished). */
	rcu_read_unlock();
}

static int axfr_query_check(struct query_data *qdata)
{
	/* Check valid zone, transaction security and contents. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);
	NS_NEED_AUTH(&qdata->zone->conf->acl.xfr_out, qdata);
	/* Check expiration. */
	NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL);

	return NS_PROC_DONE;
}

static int axfr_query_init(struct query_data *qdata)
{
	assert(qdata);

	/* Check AXFR query validity. */
	int state = axfr_query_check(qdata);
	if (state == NS_PROC_FAIL) {
		if (qdata->rcode == KNOT_RCODE_FORMERR) {
			return KNOT_EMALF;
		} else {
			return KNOT_EDENIED;
		}
	}

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
	if (!zone_tree_is_empty(zone->nsec3_nodes)) {
		ptrlist_add(&axfr->proc.nodes, zone->nsec3_nodes, mm);
	}

	/* Set up cleanup callback. */
	qdata->ext = axfr;
	qdata->ext_cleanup = &axfr_query_cleanup;

	/* No zone changes during multipacket answer
	   (unlocked in axfr_answer_cleanup) */
	rcu_read_lock();

	return KNOT_EOK;
}

int xfr_process_list(knot_pkt_t *pkt, xfr_put_cb process_item,
                     struct query_data *qdata)
{
	if (pkt == NULL || qdata == NULL || qdata->ext == NULL) {
		return KNOT_EINVAL;
	}

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
	QUERY_LOG(severity, qdata, "AXFR, outgoing", msg)

int axfr_query_process(knot_pkt_t *pkt, struct query_data *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return NS_PROC_FAIL;
	}

	int ret = KNOT_EOK;
	struct timeval now = {0};

	/* If AXFR is disabled, respond with NOTIMPL. */
	if (qdata->param->proc_flags & NS_QUERY_NO_AXFR) {
		qdata->rcode = KNOT_RCODE_NOTIMPL;
		return NS_PROC_FAIL;
	}

	/* Initialize on first call. */
	if (qdata->ext == NULL) {

		ret = axfr_query_init(qdata);
		if (ret != KNOT_EOK) {
			AXFROUT_LOG(LOG_ERR, "failed to start (%s)",
			            knot_strerror(ret));
			return NS_PROC_FAIL;
		} else {
			AXFROUT_LOG(LOG_INFO, "started, serial %u",
			           zone_contents_serial(qdata->zone->contents));
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
		AXFROUT_LOG(LOG_INFO,
		            "finished, %.02f seconds, %u messages, %u bytes",
		            time_diff(&axfr->proc.tstamp, &now) / 1000.0,
		            axfr->proc.npkts, axfr->proc.nbytes);
		return NS_PROC_DONE;
		break;
	default:          /* Generic error. */
		AXFROUT_LOG(LOG_ERR, "failed (%s)", knot_strerror(ret));
		return NS_PROC_FAIL;
	}
}
#undef AXFROUT_LOG

static void axfr_answer_cleanup(struct answer_data *data)
{
	assert(data != NULL);

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

/* AXFR-specific logging (internal, expects 'adata' variable set). */
#define AXFRIN_LOG(severity, msg...) \
	ANSWER_LOG(severity, adata, "AXFR, incoming", msg)

static int axfr_answer_finalize(struct answer_data *adata)
{
	struct timeval now;
	gettimeofday(&now, NULL);

	/*
	 * Adjust zone so that node count is set properly and nodes are
	 * marked authoritative / delegation point.
	 */
	struct xfr_proc *proc = adata->ext;
	int rc = zone_contents_adjust_full(proc->contents, NULL, NULL);
	if (rc != KNOT_EOK) {
		return rc;
	}

	size_t size_limit = adata->param->zone->conf->max_zone_size;

	if (proc->contents->size > size_limit) {
		AXFRIN_LOG(LOG_WARNING, "zone size exceeded,xx %llu", proc->contents->size);
		return NS_PROC_FAIL;
	}

	/* Switch contents. */
	zone_t *zone = adata->param->zone;
	zone_contents_t *old_contents =
	                zone_switch_contents(zone, proc->contents);
	zone->flags &= ~ZONE_EXPIRED;
	synchronize_rcu();

	AXFRIN_LOG(LOG_INFO, "finished, "
	           "serial %u -> %u, %.02f seconds, %u messages, %u bytes",
	           zone_contents_serial(old_contents),
	           zone_contents_serial(proc->contents),
	           time_diff(&proc->tstamp, &now) / 1000.0,
	           proc->npkts, proc->nbytes);

	/* Do not free new contents with cleanup. */
	zone_contents_deep_free(&old_contents);
	proc->contents = NULL;

	return KNOT_EOK;
}

static int axfr_answer_packet(knot_pkt_t *pkt, struct answer_data *adata)
{
	assert(adata != NULL);
	struct xfr_proc *proc = adata->ext;
	assert(pkt != NULL);
	assert(proc != NULL);

	/* Update counters. */
	proc->npkts  += 1;
	proc->nbytes += pkt->size;

	size_t size_limit = adata->param->zone->conf->max_zone_size;

	/* Init zone creator. */
	zcreator_t zc = {.z = proc->contents, .master = false, .ret = KNOT_EOK };

	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	for (uint16_t i = 0; i < answer->count; ++i) {

		const knot_rrset_t *rr = &answer->rr[i];
		if (rr->type == KNOT_RRTYPE_SOA &&
		    node_rrtype_exists(zc.z->apex, KNOT_RRTYPE_SOA)) {
			return NS_PROC_DONE;
		} else {
			int ret = zcreator_step(&zc, rr);
			if (ret != KNOT_EOK) {
				return NS_PROC_FAIL;
			}
		}
		proc->contents->size += knot_rrset_size(rr);
		if (proc->contents->size > size_limit) {
			AXFRIN_LOG(LOG_WARNING, "zone size exceeded");
			return NS_PROC_FAIL;
		}
		log_zone_debug(proc->contents->apex->owner, "size: %llu", proc->contents->size);
	}

	return NS_PROC_MORE;
}

int axfr_answer_process(knot_pkt_t *pkt, struct answer_data *adata)
{
	if (pkt == NULL || adata == NULL) {
		return NS_PROC_FAIL;
	}

	/* Check RCODE. */
	uint8_t rcode = knot_wire_get_rcode(pkt->wire);
	if (rcode != KNOT_RCODE_NOERROR) {
		knot_lookup_table_t *lut = knot_lookup_by_id(knot_rcode_names, rcode);
		if (lut != NULL) {
			AXFRIN_LOG(LOG_ERR, "server responded with %s", lut->name);
		}
		return NS_PROC_FAIL;
	}

	/* Initialize processing with first packet. */
	if (adata->ext == NULL) {
		NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 0);
		AXFRIN_LOG(LOG_INFO, "starting");

		int ret = axfr_answer_init(adata);
		if (ret != KNOT_EOK) {
			AXFRIN_LOG(LOG_ERR, "failed (%s)", knot_strerror(ret));
			return NS_PROC_FAIL;
		}
	} else {
		NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 100);
	}

	/* Process answer packet. */
	int ret = axfr_answer_packet(pkt, adata);
	if (ret == NS_PROC_DONE) {
		NS_NEED_TSIG_SIGNED(&adata->param->tsig_ctx, 0);
		/* This was the last packet, finalize zone and publish it. */
		int fret = axfr_answer_finalize(adata);
		if (fret != KNOT_EOK) {
			ret = NS_PROC_FAIL;
		}
	}

	return ret;
}

#undef AXFRIN_LOG
