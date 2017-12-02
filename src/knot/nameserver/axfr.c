/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/mempattern.h"
#include "contrib/sockaddr.h"
#include "knot/nameserver/axfr.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/log.h"
#include "knot/nameserver/xfr.h"
#include "libknot/libknot.h"

#define ZONE_NAME(qdata) knot_pkt_qname((qdata)->query)
#define REMOTE(qdata) (struct sockaddr *)(qdata)->params->remote

#define AXFROUT_LOG(priority, qdata, fmt...) \
	ns_log(priority, ZONE_NAME(qdata), LOG_OPERATION_AXFR, \
	       LOG_DIRECTION_OUT, REMOTE(qdata), fmt)

/* AXFR context. @note aliasing the generic xfr_proc */
struct axfr_proc {
	struct xfr_proc proc;
	trie_it_t *i;
	unsigned cur_rrset;
};

static int axfr_put_rrsets(knot_pkt_t *pkt, zone_node_t *node,
                           struct axfr_proc *state)
{
	assert(node != NULL);

	/* Append all RRs. */
	for (unsigned i = state->cur_rrset; i < node->rrset_count; ++i) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		if (rrset.type == KNOT_RRTYPE_SOA) {
			continue;
		}

		int ret = knot_pkt_put(pkt, 0, &rrset, KNOT_PF_NOTRUNC);
		if (ret != KNOT_EOK) {
			/* If something failed, remember the current RR for later. */
			state->cur_rrset = i;
			return ret;
		}
	}

	state->cur_rrset = 0;

	return KNOT_EOK;
}

static int axfr_process_node_tree(knot_pkt_t *pkt, const void *item,
                                  struct xfr_proc *state)
{
	assert(item != NULL);

	struct axfr_proc *axfr = (struct axfr_proc*)state;

	if (axfr->i == NULL) {
		axfr->i = trie_it_begin((trie_t *)item);
	}

	/* Put responses. */
	int ret = KNOT_EOK;
	while (!trie_it_finished(axfr->i)) {
		zone_node_t *node = (zone_node_t *)*trie_it_val(axfr->i);
		ret = axfr_put_rrsets(pkt, node, axfr);
		if (ret != KNOT_EOK) {
			break;
		}
		trie_it_next(axfr->i);
	}

	/* Finished all nodes. */
	if (ret == KNOT_EOK) {
		trie_it_free(axfr->i);
		axfr->i = NULL;
	}
	return ret;
}

static void axfr_query_cleanup(knotd_qdata_t *qdata)
{
	struct axfr_proc *axfr = (struct axfr_proc *)qdata->extra->ext;

	trie_it_free(axfr->i);
	ptrlist_free(&axfr->proc.nodes, qdata->mm);
	mm_free(qdata->mm, axfr);

	/* Allow zone changes (finished). */
	rcu_read_unlock();
}

static int axfr_query_check(knotd_qdata_t *qdata)
{
	NS_NEED_ZONE(qdata, KNOT_RCODE_NOTAUTH);
	NS_NEED_AUTH(qdata, qdata->extra->zone->name, ACL_ACTION_TRANSFER);
	NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL);

	return KNOT_STATE_DONE;
}

static int axfr_query_init(knotd_qdata_t *qdata)
{
	assert(qdata);

	/* Check AXFR query validity. */
	if (axfr_query_check(qdata) == KNOT_STATE_FAIL) {
		if (qdata->rcode == KNOT_RCODE_FORMERR) {
			return KNOT_EMALF;
		} else {
			return KNOT_EDENIED;
		}
	}

	/* Create transfer processing context. */
	knot_mm_t *mm = qdata->mm;
	struct axfr_proc *axfr = mm_alloc(mm, sizeof(struct axfr_proc));
	if (axfr == NULL) {
		return KNOT_ENOMEM;
	}
	memset(axfr, 0, sizeof(struct axfr_proc));
	init_list(&axfr->proc.nodes);

	/* Put data to process. */
	xfr_stats_begin(&axfr->proc.stats);
	zone_contents_t *zone = qdata->extra->zone->contents;
	ptrlist_add(&axfr->proc.nodes, zone->nodes, mm);
	/* Put NSEC3 data if exists. */
	if (!zone_tree_is_empty(zone->nsec3_nodes)) {
		ptrlist_add(&axfr->proc.nodes, zone->nsec3_nodes, mm);
	}

	/* Set up cleanup callback. */
	qdata->extra->ext = axfr;
	qdata->extra->ext_cleanup = &axfr_query_cleanup;

	/* No zone changes during multipacket answer (unlocked in axfr_answer_cleanup) */
	rcu_read_lock();

	return KNOT_EOK;
}

int axfr_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* If AXFR is disabled, respond with NOTIMPL. */
	if (qdata->params->flags & KNOTD_QUERY_FLAG_NO_AXFR) {
		qdata->rcode = KNOT_RCODE_NOTIMPL;
		return KNOT_STATE_FAIL;
	}

	/* Initialize on first call. */
	struct axfr_proc *axfr = qdata->extra->ext;
	if (axfr == NULL) {
		int ret = axfr_query_init(qdata);
		axfr = qdata->extra->ext;
		switch (ret) {
		case KNOT_EOK:      /* OK */
			AXFROUT_LOG(LOG_INFO, qdata, "started, serial %u",
			            zone_contents_serial(qdata->extra->zone->contents));
			break;
		case KNOT_EDENIED:  /* Not authorized, already logged. */
			return KNOT_STATE_FAIL;
		case KNOT_EMALF:    /* Malformed query. */
			AXFROUT_LOG(LOG_DEBUG, qdata, "malformed query");
			return KNOT_STATE_FAIL;
		default:
			AXFROUT_LOG(LOG_ERR, qdata, "failed to start (%s)",
			            knot_strerror(ret));
			return KNOT_STATE_FAIL;
		}
	}

	/* Reserve space for TSIG. */
	int ret = knot_pkt_reserve(pkt, knot_tsig_wire_size(&qdata->sign.tsig_key));
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Answer current packet (or continue). */
	ret = xfr_process_list(pkt, &axfr_process_node_tree, qdata);
	switch (ret) {
	case KNOT_ESPACE: /* Couldn't write more, send packet and continue. */
		return KNOT_STATE_PRODUCE; /* Check for more. */
	case KNOT_EOK:    /* Last response. */
		xfr_stats_end(&axfr->proc.stats);
		xfr_log_finished(ZONE_NAME(qdata), LOG_OPERATION_AXFR, LOG_DIRECTION_OUT,
		                 REMOTE(qdata), &axfr->proc.stats);
		return KNOT_STATE_DONE;
	default:          /* Generic error. */
		AXFROUT_LOG(LOG_ERR, qdata, "failed (%s)", knot_strerror(ret));
		return KNOT_STATE_FAIL;
	}
}
