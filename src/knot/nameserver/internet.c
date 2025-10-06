/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/libknot.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/nsec_proofs.h"
#include "knot/nameserver/query_module.h"
#include "knot/zone/serial.h"
#include "contrib/mempattern.h"
#include "knot/nameserver/query_state.h"

#define HINFO_RDLEN 9
static const uint8_t HINFO_RDATA[HINFO_RDLEN] = { 0x07, 'r', 'f', 'c', '8', '4', '8', '2', 0x00 };

/*! \brief Check if given node was already visited. */
static int wildcard_has_visited(knotd_qdata_t *qdata, const zone_node_t *node)
{
	struct wildcard_hit *item;
	WALK_LIST(item, qdata->extra->wildcards) {
		if (item->node == node) {
			return true;
		}
	}
	return false;
}

/*! \brief Mark given node as visited. */
static int wildcard_visit(knotd_qdata_t *qdata, const zone_node_t *node,
                          const zone_node_t *prev, const knot_dname_t *sname)
{
	assert(qdata);
	assert(node);

	if (node->flags & NODE_FLAGS_NONAUTH) {
		return KNOT_EOK;
	}

	knot_mm_t *mm = qdata->mm;
	struct wildcard_hit *item = mm_alloc(mm, sizeof(struct wildcard_hit));
	item->node = node;
	item->prev = prev;
	item->sname = sname;
	add_tail(&qdata->extra->wildcards, (node_t *)item);
	return KNOT_EOK;
}

/*! \brief Synthetizes a CNAME RR from a DNAME. */
static int dname_cname_synth(const knot_rrset_t *dname_rr,
                             const knot_dname_t *qname,
                             knot_rrset_t *cname_rrset,
                             knot_mm_t *mm)
{
	if (cname_rrset == NULL) {
		return KNOT_EINVAL;
	}
	knot_dname_t *owner_copy = knot_dname_copy(qname, mm);
	if (owner_copy == NULL) {
		return KNOT_ENOMEM;
	}
	knot_rrset_init(cname_rrset, owner_copy, KNOT_RRTYPE_CNAME, dname_rr->rclass,
	                dname_rr->ttl);

	/* Replace last labels of qname with DNAME. */
	const knot_dname_t *dname_wire = dname_rr->owner;
	const knot_dname_t *dname_tgt = knot_dname_target(dname_rr->rrs.rdata);
	size_t labels = knot_dname_labels(dname_wire, NULL);
	knot_dname_t *cname = knot_dname_replace_suffix(qname, labels, dname_tgt, mm);
	if (cname == NULL) {
		knot_dname_free(owner_copy, mm);
		return KNOT_ENOMEM;
	}

	/* Store DNAME into RDATA. */
	size_t cname_size = knot_dname_size(cname);
	uint8_t cname_rdata[cname_size];
	memcpy(cname_rdata, cname, cname_size);
	knot_dname_free(cname, mm);

	int ret = knot_rrset_add_rdata(cname_rrset, cname_rdata, cname_size, mm);
	if (ret != KNOT_EOK) {
		knot_dname_free(owner_copy, mm);
		return ret;
	}

	return KNOT_EOK;
}

/*!
 * \brief Checks if the name created by replacing the owner of \a dname_rrset
 *        in the \a qname by the DNAME's target would be longer than allowed.
 */
static bool dname_cname_cannot_synth(const knot_rrset_t *rrset, const knot_dname_t *qname)
{
	if (knot_dname_labels(qname, NULL) - knot_dname_labels(rrset->owner, NULL) +
	    knot_dname_labels(knot_dname_target(rrset->rrs.rdata), NULL) > KNOT_DNAME_MAXLABELS) {
		return true;
	} else if (knot_dname_size(qname) - knot_dname_size(rrset->owner) +
	           knot_dname_size(knot_dname_target(rrset->rrs.rdata)) > KNOT_DNAME_MAXLEN) {
		return true;
	} else {
		return false;
	}
}

/*! \brief DNSSEC both requested & available. */
static bool have_dnssec(knotd_qdata_t *qdata)
{
	return knot_pkt_has_dnssec(qdata->query) &&
	       (qdata->extra->contents->dnssec || qdata->extra->zone->sign_ctx != NULL);
}

/*! \brief This is a wildcard-covered or any other terminal node for QNAME.
 *         e.g. positive answer.
 */
static int put_answer(knot_pkt_t *pkt, uint16_t type, knotd_qdata_t *qdata)
{
	/* Wildcard expansion or exact match, either way RRSet owner is
	 * is QNAME. We can fake name synthesis by setting compression hint to
	 * QNAME position. Just need to check if we're answering QNAME and not
	 * a CNAME target.
	 */
	uint16_t compr_hint = KNOT_COMPR_HINT_NONE;
	if (pkt->rrset_count == 0) { /* Guaranteed first answer. */
		compr_hint = KNOT_COMPR_HINT_QNAME;
	}

	unsigned put_rr_flags = (qdata->params->flags & KNOTD_QUERY_FLAG_LIMIT_SIZE) ?
	                        KNOT_PF_NULL : KNOT_PF_NOTRUNC;
	put_rr_flags |= KNOT_PF_ORIGTTL;

	knot_rrset_t rrsigs = node_rrset(qdata->extra->node, KNOT_RRTYPE_RRSIG);

	knot_rrset_t rrset;
	switch (type) {
	case KNOT_RRTYPE_ANY: /* Put one RRSet, not all. */
		if (conf()->cache.srv_disable_any)
		{
			knot_rrset_init(&rrset, qdata->extra->node->owner, KNOT_RRTYPE_HINFO, KNOT_CLASS_IN, 300);
			int r = knot_rrset_add_rdata(&rrset, HINFO_RDATA, HINFO_RDLEN,  qdata->mm);
			if (r != KNOT_EOK) {
				return r;
			}
		}
		else {
			rrset = node_rrset_at(qdata->extra->node, 0);
		}
		break;
	case KNOT_RRTYPE_RRSIG: /* Put some RRSIGs, not all. */
		if (!knot_rrset_empty(&rrsigs)) {
			knot_rrset_init(&rrset, rrsigs.owner, rrsigs.type, rrsigs.rclass, rrsigs.ttl);
			int ret = knot_synth_rrsig(KNOT_RRTYPE_ANY, &rrsigs.rrs, &rrset.rrs, qdata->mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		} else {
			knot_rrset_init_empty(&rrset);
		}
		break;
	default: /* Single RRSet of given type. */
		rrset = node_rrset(qdata->extra->node, type);
		break;
	}

	if (knot_rrset_empty(&rrset)) {
		return KNOT_EOK;
	}

	return process_query_put_rr(pkt, qdata, &rrset, &rrsigs, compr_hint, put_rr_flags);
}

/*! \brief Puts optional SOA RRSet to the Authority section of the response. */
static int put_authority_soa(knot_pkt_t *pkt, knotd_qdata_t *qdata,
                             const zone_contents_t *zone)
{
	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t rrsigs = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
	return process_query_put_rr(pkt, qdata, &soa, &rrsigs,
	                            KNOT_COMPR_HINT_NONE,
	                            KNOT_PF_NOTRUNC | KNOT_PF_SOAMINTTL);
}

/*! \brief Put the delegation NS RRSet to the Authority section. */
static int put_delegation(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	/* Find closest delegation point. */
	while (!(qdata->extra->node->flags & NODE_FLAGS_DELEG)) {
		qdata->extra->node = node_parent(qdata->extra->node);
	}

	/* Insert NS record. */
	knot_rrset_t rrset = node_rrset(qdata->extra->node, KNOT_RRTYPE_NS);
	knot_rrset_t rrsigs = node_rrset(qdata->extra->node, KNOT_RRTYPE_RRSIG);
	return process_query_put_rr(pkt, qdata, &rrset, &rrsigs,
	                            KNOT_COMPR_HINT_NONE, 0);
}

/*! \brief Put additional records for given RR. */
static int put_additional(knot_pkt_t *pkt, const knot_rrset_t *rr,
                          knotd_qdata_t *qdata, knot_rrinfo_t *info, int state)
{
	if (rr->additional == NULL) {
		return KNOT_EOK;
	}

	/* Valid types for ADDITIONALS insertion. */
	/* \note Not resolving CNAMEs as MX/NS name must not be an alias. (RFC2181/10.3) */
	static const uint16_t ar_type_list[] = { KNOT_RRTYPE_A, KNOT_RRTYPE_AAAA };
	static const int ar_type_count = 2;

	int ret = KNOT_EOK;

	additional_t *additional = (additional_t *)rr->additional;

	/* Iterate over the additionals. */
	for (uint16_t i = 0; i < additional->count; i++) {
		glue_t *glue = &additional->glues[i];
		uint32_t flags = KNOT_PF_NULL;

		/* Optional glue doesn't cause truncation. (RFC 1034/4.3.2 step 3b). */
		if (state != KNOTD_IN_STATE_DELEG || glue->optional) {
			flags |= KNOT_PF_NOTRUNC;
		}

		uint16_t hint = knot_compr_hint(info, KNOT_COMPR_HINT_RDATA +
		                                glue->ns_pos);
		const zone_node_t *gluenode = glue_node(glue, qdata->extra->node);
		knot_rrset_t rrsigs = node_rrset(gluenode, KNOT_RRTYPE_RRSIG);
		for (int k = 0; k < ar_type_count; ++k) {
			knot_rrset_t rrset = node_rrset(gluenode, ar_type_list[k]);
			if (knot_rrset_empty(&rrset)) {
				continue;
			}
			ret = process_query_put_rr(pkt, qdata, &rrset, &rrsigs,
			                           hint, flags);
			if (ret != KNOT_EOK) {
				break;
			}
		}
	}

	return ret;
}

static int follow_cname(knot_pkt_t *pkt, uint16_t rrtype, knotd_qdata_t *qdata)
{
	/* CNAME chain processing limit. */
	if (++qdata->extra->cname_chain > CNAME_CHAIN_MAX) {
		qdata->extra->node = NULL;
		return KNOTD_IN_STATE_HIT;
	}

	const zone_node_t *cname_node = qdata->extra->node;
	knot_rrset_t cname_rr = node_rrset(qdata->extra->node, rrtype);
	knot_rrset_t rrsigs = node_rrset(qdata->extra->node, KNOT_RRTYPE_RRSIG);

	assert(!knot_rrset_empty(&cname_rr));

	/* Check whether RR is already in the packet. */
	uint16_t flags = KNOT_PF_CHECKDUP;

	/* Now, try to put CNAME to answer. */
	uint16_t rr_count_before = pkt->rrset_count;
	int ret = process_query_put_rr(pkt, qdata, &cname_rr, &rrsigs, 0, flags);
	switch (ret) {
	case KNOT_EOK:    break;
	case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC;
	default:          return KNOTD_IN_STATE_ERROR;
	}

	/* Synthesize CNAME if followed DNAME. */
	if (rrtype == KNOT_RRTYPE_DNAME) {
		if (dname_cname_cannot_synth(&cname_rr, qdata->name)) {
			qdata->rcode = KNOT_RCODE_YXDOMAIN;
		} else {
			knot_rrset_t dname_rr = cname_rr;
			ret = dname_cname_synth(&dname_rr, qdata->name,
			                        &cname_rr, &pkt->mm);
			if (ret != KNOT_EOK) {
				qdata->rcode = KNOT_RCODE_SERVFAIL;
				return KNOTD_IN_STATE_ERROR;
			}
			ret = process_query_put_rr(pkt, qdata, &cname_rr, NULL, 0, KNOT_PF_FREE);
			switch (ret) {
			case KNOT_EOK:    break;
			case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC;
			default:          return KNOTD_IN_STATE_ERROR;
			}
			if (knot_pkt_qtype(pkt) == KNOT_RRTYPE_CNAME) {
				/* Synthesized CNAME is a perfect answer to query. */
				return KNOTD_IN_STATE_HIT;
			}
		}
	}

	/* Check if RR count increased. */
	if (pkt->rrset_count <= rr_count_before) {
		qdata->extra->node = NULL; /* Act as if the name leads to nowhere. */
		return KNOTD_IN_STATE_HIT;
	}

	/* If node is a wildcard, follow only if we didn't visit the same node
	 * earlier, as that would mean a CNAME loop. */
	if (knot_dname_is_wildcard(cname_node->owner)) {

		/* Check if is not in wildcard nodes (loop). */
		if (wildcard_has_visited(qdata, cname_node)) {
			qdata->extra->node = NULL; /* Act as if the name leads to nowhere. */

			if (wildcard_visit(qdata, cname_node, qdata->extra->previous, qdata->name) != KNOT_EOK) { // in case of loop, re-add this cname_node because it might have different qdata->name
				return KNOTD_IN_STATE_ERROR;
			}
			return KNOTD_IN_STATE_HIT;
		}

		/* Put to wildcard node list. */
		if (wildcard_visit(qdata, cname_node, qdata->extra->previous, qdata->name) != KNOT_EOK) {
			return KNOTD_IN_STATE_ERROR;
		}
	}

	/* Now follow the next CNAME TARGET. */
	qdata->name = knot_cname_name(cname_rr.rrs.rdata);

	return KNOTD_IN_STATE_FOLLOW;
}

static int name_found(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	uint16_t qtype = knot_pkt_qtype(pkt);

	/* DS query at DP is answered normally, but everything else at/below DP
	 * triggers referral response. */
	if (((qdata->extra->node->flags & NODE_FLAGS_DELEG) && qtype != KNOT_RRTYPE_DS) ||
	    (qdata->extra->node->flags & NODE_FLAGS_NONAUTH)) {
		return KNOTD_IN_STATE_DELEG;
	}

	if (node_rrtype_exists(qdata->extra->node, KNOT_RRTYPE_CNAME)
	    && qtype != KNOT_RRTYPE_CNAME
	    && qtype != KNOT_RRTYPE_RRSIG
	    && qtype != KNOT_RRTYPE_NSEC
	    && qtype != KNOT_RRTYPE_ANY) {
		int ret = follow_cname(pkt, KNOT_RRTYPE_CNAME, qdata);
		if (ret == KNOTD_IN_STATE_FOLLOW) {
			/* No need to follow, as the CNAME chain is disabled. */
			return KNOTD_IN_STATE_HIT;
		}

		return ret;
	}

	uint16_t old_rrcount = pkt->rrset_count;
	int ret = put_answer(pkt, qtype, qdata);
	if (ret != KNOT_EOK) {
		if (ret == KNOT_ESPACE && (qdata->params->flags & KNOTD_QUERY_FLAG_LIMIT_SIZE)) {
			return KNOTD_IN_STATE_TRUNC;
		} else {
			return KNOTD_IN_STATE_ERROR;
		}
	}

	/* Check for NODATA (=0 RRs added). */
	if (old_rrcount == pkt->rrset_count) {
		return KNOTD_IN_STATE_NODATA;
	} else {
		return KNOTD_IN_STATE_HIT;
	}
}

static int name_not_found(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	/* Name is covered by wildcard. */
	if (qdata->extra->encloser->flags & NODE_FLAGS_WILDCARD_CHILD) {
		/* Find wildcard child in the zone. */
		const zone_node_t *wildcard_node =
			zone_contents_find_wildcard_child(
				qdata->extra->contents, qdata->extra->encloser);

		qdata->extra->node = wildcard_node;
		assert(qdata->extra->node != NULL);

		/* Follow expanded wildcard. */
		int next_state = name_found(pkt, qdata);

		/* Put to wildcard node list. */
		if (wildcard_has_visited(qdata, wildcard_node)) {
			return next_state;
		}
		if (wildcard_visit(qdata, wildcard_node, qdata->extra->previous, qdata->name) != KNOT_EOK) {
			next_state = KNOTD_IN_STATE_ERROR;
		}

		return next_state;
	}

	/* Name is under DNAME, use it for substitution. */
	bool encloser_auth = !(qdata->extra->encloser->flags & (NODE_FLAGS_NONAUTH | NODE_FLAGS_DELEG));
	knot_rrset_t dname_rrset = node_rrset(qdata->extra->encloser, KNOT_RRTYPE_DNAME);
	if (encloser_auth && !knot_rrset_empty(&dname_rrset)) {
		qdata->extra->node = qdata->extra->encloser; /* Follow encloser as new node. */
		return follow_cname(pkt, KNOT_RRTYPE_DNAME, qdata);
	}

	/* Look up an authoritative encloser or its parent. */
	const zone_node_t *node = qdata->extra->encloser;
	while (node->rrset_count == 0 || node->flags & NODE_FLAGS_NONAUTH) {
		node = node_parent(node);
		assert(node);
	}

	/* Name is below delegation. */
	if ((node->flags & NODE_FLAGS_DELEG)) {
		qdata->extra->node = node;
		return KNOTD_IN_STATE_DELEG;
	}

	return KNOTD_IN_STATE_MISS;
}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
#define HANDLE_ASYNC_STATE(state) \
    if (state == KNOTD_IN_STATE_ASYNC) { \
	    return KNOT_STATE_ASYNC; \
	}
#else
#define HANDLE_ASYNC_STATE(state)
#endif

#define HANDLE_STATE(state, state_machine) \
    { \
		if (state == KNOTD_IN_STATE_TRUNC) { \
			(state_machine)->step = NULL; \
			return KNOT_STATE_DONE; \
		} else if (state == KNOTD_IN_STATE_ERROR) { \
			(state_machine)->step = NULL; \
			return KNOT_STATE_FAIL; \
		} \
		HANDLE_ASYNC_STATE(state) \
	}

/*! \brief Helper for internet_query repetitive code. */
#define SOLVE_STEP(solver, state, context, state_machine) \
	state = (solver)(state, pkt, qdata, context); \
	HANDLE_STATE(state, state_machine)

static int solve_name(int state, knot_pkt_t *pkt, knotd_qdata_t *qdata, state_machine_t *state_machine)
{
	struct query_plan *plan = conf()->query_plan;
	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_name_state, SOLVE_NAME_HANDLE_INCOMING_STATE) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_name_state, SOLVE_NAME_HANDLE_INCOMING_STATE);
		state_machine->solve_name_incoming_state = state;
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_name_state, SOLVE_NAME_STAGE_LOOKUP) {
		if (plan != NULL) {
			WALK_LIST_RESUME(state_machine->step, plan->stage[KNOTD_STAGE_NAME_LOOKUP]) {
				state = state_machine->step->process(state, pkt, qdata, state_machine->step->ctx);
				HANDLE_ASYNC_STATE(state);
			}
		}
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_name_state, SOLVE_NAME_STAGE_LOOKUP);
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_name_state, SOLVE_NAME_STAGE_LOOKUP_DONE) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_name_state, SOLVE_NAME_STATE_BEGIN); // reset state so next call will execute from beginning
		int ret;
		if (state == KNOTD_IN_STATE_ERROR)
		{
			return state;
		}
		else if (state == KNOTD_IN_STATE_LOOKUPDONE)
		{
			ret = qdata->extra->ext_result;
			if (ret == KNOT_EOUTOFZONE) {
				return KNOTD_IN_STATE_HIT;
			}
		}
		else
		{
			ret = zone_contents_find_dname(qdata->extra->contents, qdata->name,
											&qdata->extra->node, &qdata->extra->encloser,
											&qdata->extra->previous);
		}

		switch (ret) {
		case ZONE_NAME_FOUND:
			return name_found(pkt, qdata);
		case ZONE_NAME_NOT_FOUND:
			return name_not_found(pkt, qdata);
		case KNOT_EOUTOFZONE:
			assert(state_machine->solve_name_incoming_state == KNOTD_IN_STATE_FOLLOW); /* CNAME/DNAME chain only. */
			return KNOTD_IN_STATE_HIT;
		default:
			return KNOTD_IN_STATE_ERROR;
		}
	}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	return state;
#endif
}

static int solve_answer(int state, knot_pkt_t *pkt, knotd_qdata_t *qdata, state_machine_t *state_machine)
{
	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_answer_state, SOLVE_ANSWER_HANDLE_INCOMING_STATE) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_answer_state, SOLVE_ANSWER_HANDLE_INCOMING_STATE);
		state_machine->solve_answer_old_state = state;

		/* Do not solve if already solved, e.g. in a module. */
		if (state == KNOTD_IN_STATE_HIT) {
			return state;
		}
	}

	/* Get answer to QNAME. */
	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_answer_state, SOLVE_ANSWER_SOLVE_NAME_FIRST) {
		state = solve_name(state, pkt, qdata, state_machine);
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_answer_state, SOLVE_ANSWER_SOLVE_NAME_FIRST);
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_answer_state, SOLVE_ANSWER_SOLVE_NAME_FIRST_DONE) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_answer_state, SOLVE_ANSWER_SOLVE_NAME_FIRST_DONE);
		/* Promote NODATA from a module if nothing found in zone. */
		if (state == KNOTD_IN_STATE_MISS && state_machine->solve_answer_old_state == KNOTD_IN_STATE_NODATA) {
			state = state_machine->solve_answer_old_state;
		}

		/* Is authoritative answer unless referral.
		* Must check before we chase the CNAME chain. */
		if (state != KNOTD_IN_STATE_DELEG) {
			knot_wire_set_aa(pkt->wire);
		}
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_answer_state, SOLVE_ANSWER_SOLVE_NAME_FOLLOW) {
		/* Additional resolving for CNAME/DNAME chain. */
		while (state == KNOTD_IN_STATE_FOLLOW || state_machine->solve_answer_loop_in_async) {
			state_machine->solve_answer_loop_in_async = false;
			state = solve_name(state, pkt, qdata, state_machine);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
			if (state == KNOT_STATE_ASYNC) {
				state_machine->solve_answer_loop_in_async = true;
				break;
			}
#endif
		}
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, solve_answer_state, SOLVE_ANSWER_SOLVE_NAME_FOLLOW);
	}

	return state;
}

static int solve_answer_dnssec(int state, knot_pkt_t *pkt, knotd_qdata_t *qdata, void *ctx)
{
	/* RFC4035, section 3.1 RRSIGs for RRs in ANSWER are mandatory. */
	int ret = nsec_append_rrsigs(pkt, qdata, false);
	switch (ret) {
	case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC;
	case KNOT_EOK:    return state;
	default:          return KNOTD_IN_STATE_ERROR;
	}
}

static int solve_authority(int state, knot_pkt_t *pkt, knotd_qdata_t *qdata, void *ctx)
{
	int ret = KNOT_ERROR;
	const zone_contents_t *zone_contents = qdata->extra->contents;

	switch (state) {
	case KNOTD_IN_STATE_HIT:    /* Positive response. */
		ret = KNOT_EOK;
		break;
	case KNOTD_IN_STATE_MISS:   /* MISS, set NXDOMAIN RCODE. */
		qdata->rcode = KNOT_RCODE_NXDOMAIN;
		ret = put_authority_soa(pkt, qdata, zone_contents);
		break;
	case KNOTD_IN_STATE_NODATA: /* NODATA append AUTHORITY SOA. */
		ret = put_authority_soa(pkt, qdata, zone_contents);
		break;
	case KNOTD_IN_STATE_DELEG:  /* Referral response. */
		ret = put_delegation(pkt, qdata);
		break;
	case KNOTD_IN_STATE_TRUNC:  /* Truncated ANSWER. */
		ret = KNOT_ESPACE;
		break;
	case KNOTD_IN_STATE_ERROR:  /* Error resolving ANSWER. */
		break;
	default:
		assert(0);
		break;
	}

	/* Evaluate final state. */
	switch (ret) {
	case KNOT_EOK:    return state; /* Keep current state. */
	case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC; /* Truncated. */
	default:          return KNOTD_IN_STATE_ERROR; /* Error. */
	}
}

static int solve_authority_dnssec(int state, knot_pkt_t *pkt, knotd_qdata_t *qdata, void *ctx)
{
	int ret = KNOT_ERROR;

	/* Authenticated denial of existence. */
	switch (state) {
	case KNOTD_IN_STATE_HIT:    ret = KNOT_EOK; break;
	case KNOTD_IN_STATE_MISS:   ret = nsec_prove_nxdomain(pkt, qdata); break;
	case KNOTD_IN_STATE_NODATA: ret = nsec_prove_nodata(pkt, qdata); break;
	case KNOTD_IN_STATE_DELEG:  ret = nsec_prove_dp_security(pkt, qdata); break;
	case KNOTD_IN_STATE_TRUNC:  ret = KNOT_ESPACE; break;
	case KNOTD_IN_STATE_ERROR:  ret = KNOT_ERROR; break;
	default:
		assert(0);
		break;
	}

	/* RFC4035 3.1.3 Prove visited wildcards.
	 * Wildcard expansion applies for Name Error, Wildcard Answer and
	 * No Data proofs if at one point the search expanded a wildcard node. */
	if (ret == KNOT_EOK) {
		ret = nsec_prove_wildcards(pkt, qdata);
	}

	/* RFC4035, section 3.1 RRSIGs for RRs in AUTHORITY are mandatory. */
	if (ret == KNOT_EOK) {
		ret = nsec_append_rrsigs(pkt, qdata, false);
	}

	/* Evaluate final state. */
	switch (ret) {
	case KNOT_EOK:    return state; /* Keep current state. */
	case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC; /* Truncated. */
	default:          return KNOTD_IN_STATE_ERROR; /* Error. */
	}
}

static int solve_additional(int state, knot_pkt_t *pkt, knotd_qdata_t *qdata,
                            void *ctx)
{
	int ret = KNOT_EOK;

	/* Scan all RRs in ANSWER/AUTHORITY. */
	for (uint16_t i = 0; i < pkt->rrset_count; ++i) {
		knot_rrset_t *rr = &pkt->rr[i];
		knot_rrinfo_t *info = &pkt->rr_info[i];

		/* Skip types for which it doesn't apply. */
		if (!knot_rrtype_additional_needed(rr->type)) {
			continue;
		}

		/* Put additional records for given type. */
		ret = put_additional(pkt, rr, qdata, info, state);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	/* Evaluate final state. */
	switch (ret) {
	case KNOT_EOK:    return state; /* Keep current state. */
	case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC; /* Truncated. */
	default:          return KNOTD_IN_STATE_ERROR; /* Error. */
	}
}

static int solve_additional_dnssec(int state, knot_pkt_t *pkt, knotd_qdata_t *qdata, void *ctx)
{
	/* RFC4035, section 3.1 RRSIGs for RRs in ADDITIONAL are optional. */
	int ret = nsec_append_rrsigs(pkt, qdata, true);
	switch (ret) {
	case KNOT_ESPACE: return KNOTD_IN_STATE_TRUNC;
	case KNOT_EOK:    return state;
	default:          return KNOTD_IN_STATE_ERROR;
	}
}

static int answer_query(knot_pkt_t *pkt, knotd_qdata_t *qdata, state_machine_t *state_machine)
{
	int state = state_machine->process_query_next_state_in;
	// Ideally the code should handle the answer state (on resume) as part of individual path below when it resumes.
	// Since all code path below returns state immediately following failure, the next line handles all those cases for async on resume.
	// If any code path handles error differently (in the entire calltree) on resume from async, then error code should be handled by individual code path.
	HANDLE_STATE(state, state_machine);

	struct query_plan *plan = qdata->extra->zone->query_plan;

	bool with_dnssec = have_dnssec(qdata);

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_PREANSWER) {
		/* Resolve PREANSWER. */
		if (plan != NULL) {
			WALK_LIST_RESUME(state_machine->step, plan->stage[KNOTD_STAGE_PREANSWER]) {
				SOLVE_STEP(state_machine->step->process, state, state_machine->step->ctx, state_machine);
			}
		}
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_PREANSWER);
	}

	/* Resolve ANSWER. */
	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_ANSWER_BEGIN) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_ANSWER_BEGIN);
		knot_pkt_begin(pkt, KNOT_ANSWER);
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SOLVE_ANSWER) {
		state = solve_answer(state, pkt, qdata, state_machine);
		HANDLE_STATE(state, state_machine);
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SOLVE_ANSWER);
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SOLVE_ANSWER_DNSSEC) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SOLVE_ANSWER_DNSSEC);
		if (with_dnssec) {
			SOLVE_STEP(solve_answer_dnssec, state, NULL, state_machine);
		}
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_STAGE_ANSWER) {
		if (plan != NULL) {
			WALK_LIST_RESUME(state_machine->step, plan->stage[KNOTD_STAGE_ANSWER]) {
				SOLVE_STEP(state_machine->step->process, state, state_machine->step->ctx, state_machine);
			}
		}
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_STAGE_ANSWER);
	}

	/* Resolve AUTHORITY. */
	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_AUTH_BEGIN) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_AUTH_BEGIN);
		knot_pkt_begin(pkt, KNOT_AUTHORITY);
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SOLVE_AUTH) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SOLVE_AUTH);
		SOLVE_STEP(solve_authority, state, NULL, state_machine);
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SOLVE_AUTH_DNSSEC) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SOLVE_AUTH_DNSSEC);
		/* Azure onlinesign module generate nsec record based on black lies. So not calling solve_authority_dnssec to add nsec data
		   for azure online signing.
		*/
		if (with_dnssec && qdata->extra->zone->sign_ctx == NULL) {
			SOLVE_STEP(solve_authority_dnssec, state, NULL, state_machine);
		}
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_STAGE_AUTH) {
		if (plan != NULL) {
			WALK_LIST_RESUME(state_machine->step, plan->stage[KNOTD_STAGE_AUTHORITY]) {
				SOLVE_STEP(state_machine->step->process, state, state_machine->step->ctx, state_machine);
			}
		}
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_STAGE_AUTH);
	}

	/* Resolve ADDITIONAL. */
	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_ADDITIONAL_BEGIN) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_ADDITIONAL_BEGIN);
		knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SOLVE_ADDITIONAL) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SOLVE_ADDITIONAL);
		SOLVE_STEP(solve_additional, state, NULL, state_machine);
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SOLVE_AADDITIONAL_DNSSEC) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SOLVE_AADDITIONAL_DNSSEC);
		if (with_dnssec) {
			SOLVE_STEP(solve_additional_dnssec, state, NULL, state_machine);
		}
	}

	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_STAGE_AADDITIONAL) {
		if (plan != NULL) {
			WALK_LIST_RESUME(state_machine->step, plan->stage[KNOTD_STAGE_ADDITIONAL]) {
				SOLVE_STEP(state_machine->step->process, state, state_machine->step->ctx, state_machine);
			}
		}
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_STAGE_AADDITIONAL);
	}

	/* Write resulting RCODE. */
	STATE_MACHINE_RUN_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SET_ERROR) {
		STATE_MACHINE_COMPLETED_STATE(state_machine, state, KNOTD_IN_STATE_ASYNC, answer_query_state, ANSWER_QUERY_STATE_DONE_SET_ERROR);
		knot_wire_set_rcode(pkt->wire, qdata->rcode);
	}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	return state == KNOTD_IN_STATE_ASYNC ? KNOT_STATE_ASYNC : KNOT_STATE_DONE;
#else
	return KNOT_STATE_DONE;
#endif
}

int internet_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return KNOT_STATE_FAIL;
	}

	state_machine_t *state = qdata->state;

	STATE_MACHINE_RUN_STATE(state, KNOTD_STATE_ZONE_LOOKUPDONE, KNOT_STATE_ASYNC, internet_process_query_state, INTERNET_PROCESS_QUERY_STATE_DONE_PREPROCESS) {
		/* Check if rcode was already marked otherwise override it*/
		if (qdata->rcode == KNOT_RCODE_SERVFAIL)
		{
			NS_NEED_ZONE(qdata, KNOT_RCODE_SERVFAIL);;
		}

		/* Check valid zone, transaction security (optional) and contents. */
		NS_NEED_ZONE(qdata, KNOT_RCODE_REFUSED);

		/* No applicable ACL, refuse transaction security. */
		if (knot_pkt_has_tsig(qdata->query)) {
			/* We have been challenged... */
			NS_NEED_AUTH(qdata, ACL_ACTION_NONE);

			/* Reserve space for TSIG. */
			int ret = knot_pkt_reserve(pkt, knot_tsig_wire_size(&qdata->sign.tsig_key));
			if (ret != KNOT_EOK) {
				return KNOT_STATE_FAIL;
			}
		}

		NS_NEED_ZONE_CONTENTS(qdata); /* Expired */

		/* Get answer to QNAME. */
		qdata->name = knot_pkt_qname(qdata->query);
		STATE_MACHINE_COMPLETED_STATE(state, KNOTD_STATE_ZONE_LOOKUPDONE, KNOT_STATE_ASYNC, internet_process_query_state, INTERNET_PROCESS_QUERY_STATE_DONE_PREPROCESS);
	}

	return answer_query(pkt, qdata, state);
}
