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

#include "libknot/libknot.h"
#include "knot/common/log.h"
#include "knot/query/query.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/nsec_proofs.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/query_module.h"
#include "knot/zone/serial.h"
#include "contrib/mempattern.h"

/*! \brief Check if given node was already visited. */
static int wildcard_has_visited(struct query_data *qdata, const zone_node_t *node)
{
	struct wildcard_hit *item = NULL;
	WALK_LIST(item, qdata->wildcards) {
		if (item->node == node) {
			return true;
		}
	}
	return false;
}

/*! \brief Mark given node as visited. */
static int wildcard_visit(struct query_data *qdata, const zone_node_t *node,
                          const zone_node_t *prev, const knot_dname_t *sname)
{
	assert(qdata);
	assert(node);

	/* Already in the list. */
	if (wildcard_has_visited(qdata, node)) {
		return KNOT_EOK;
	}

	knot_mm_t *mm = qdata->mm;
	struct wildcard_hit *item = mm_alloc(mm, sizeof(struct wildcard_hit));
	item->node = node;
	item->prev = prev;
	item->sname = sname;
	add_tail(&qdata->wildcards, (node_t *)item);
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
	knot_rrset_init(cname_rrset, owner_copy, KNOT_RRTYPE_CNAME, dname_rr->rclass);

	/* Replace last labels of qname with DNAME. */
	const knot_dname_t *dname_wire = dname_rr->owner;
	const knot_dname_t *dname_tgt = knot_dname_target(&dname_rr->rrs);
	int labels = knot_dname_labels(dname_wire, NULL);
	knot_dname_t *cname = knot_dname_replace_suffix(qname, labels, dname_tgt);
	if (cname == NULL) {
		knot_dname_free(&owner_copy, mm);
		return KNOT_ENOMEM;
	}

	/* Store DNAME into RDATA. */
	int cname_size = knot_dname_size(cname);
	uint8_t cname_rdata[cname_size];
	memcpy(cname_rdata, cname, cname_size);
	knot_dname_free(&cname, NULL);

	const knot_rdata_t *dname_data = knot_rdataset_at(&dname_rr->rrs, 0);
	int ret = knot_rrset_add_rdata(cname_rrset, cname_rdata, cname_size,
	                               knot_rdata_ttl(dname_data), mm);
	if (ret != KNOT_EOK) {
		knot_dname_free(&owner_copy, mm);
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
	    knot_dname_labels(knot_dname_target(&rrset->rrs), NULL) > KNOT_DNAME_MAXLABELS) {
		return true;
	} else if (knot_dname_size(qname) - knot_dname_size(rrset->owner) +
	           knot_dname_size(knot_dname_target(&rrset->rrs)) > KNOT_DNAME_MAXLEN) {
		return true;
	} else {
		return false;
	}
}

/*! \brief DNSSEC both requested & available. */
static bool have_dnssec(struct query_data *qdata)
{
	return knot_pkt_has_dnssec(qdata->query) &&
	       zone_contents_is_signed(qdata->zone->contents);
}

/*! \brief This is a wildcard-covered or any other terminal node for QNAME.
 *         e.g. positive answer.
 */
static int put_answer(knot_pkt_t *pkt, uint16_t type, struct query_data *qdata)
{
	knot_rrset_t rrset;
	knot_rrset_init_empty(&rrset);

	/* Wildcard expansion or exact match, either way RRSet owner is
	 * is QNAME. We can fake name synthesis by setting compression hint to
	 * QNAME position. Just need to check if we're answering QNAME and not
	 * a CNAME target.
	 */
	uint16_t compr_hint = KNOT_COMPR_HINT_NONE;
	if (pkt->rrset_count == 0) { /* Guaranteed first answer. */
		compr_hint = KNOT_COMPR_HINT_QNAME;
	}

	unsigned put_rr_flags = (qdata->param->proc_flags & NS_QUERY_LIMIT_SIZE) ?
	                        KNOT_PF_NULL : KNOT_PF_NOTRUNC;

	int ret = KNOT_EOK;
	switch (type) {
	case KNOT_RRTYPE_ANY: /* Append all RRSets. */ {
		conf_val_t val = conf_zone_get(conf(), C_DISABLE_ANY,
		                               qdata->zone->name);
		/* If ANY not allowed, set TC bit. */
		if ((qdata->param->proc_flags & NS_QUERY_LIMIT_ANY) &&
		    conf_bool(&val)) {
			knot_wire_set_tc(pkt->wire);
			return KNOT_ESPACE;
		}
		for (unsigned i = 0; i < qdata->node->rrset_count; ++i) {
			rrset = node_rrset_at(qdata->node, i);
			ret = process_query_put_rr(pkt, qdata, &rrset, NULL,
			                           compr_hint, put_rr_flags);
			if (ret != KNOT_EOK) {
				break;
			}
		}
		break;
	}
	default: /* Single RRSet of given type. */
		rrset = node_rrset(qdata->node, type);
		if (!knot_rrset_empty(&rrset)) {
			knot_rrset_t rrsigs = node_rrset(qdata->node, KNOT_RRTYPE_RRSIG);
			ret = process_query_put_rr(pkt, qdata, &rrset, &rrsigs,
			                           compr_hint, put_rr_flags);
		}
		break;
	}

	return ret;
}

/*! \brief Puts optional SOA RRSet to the Authority section of the response. */
static int put_authority_soa(knot_pkt_t *pkt, struct query_data *qdata,
                             const zone_contents_t *zone)
{
	knot_rrset_t soa_rrset = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t rrsigs = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);

	// if SOA's TTL is larger than MINIMUM, copy the RRSet and set
	// MINIMUM as TTL
	int ret = KNOT_EOK;
	uint32_t flags = KNOT_PF_NOTRUNC;
	uint32_t min = knot_soa_minimum(&soa_rrset.rrs);
	const knot_rdata_t *soa_data = knot_rdataset_at(&soa_rrset.rrs, 0);
	if (min < knot_rdata_ttl(soa_data)) {
		knot_rrset_t copy;
		knot_dname_t *dname_cpy = knot_dname_copy(soa_rrset.owner, &pkt->mm);
		if (dname_cpy == NULL) {
			return KNOT_ENOMEM;
		}
		knot_rrset_init(&copy, dname_cpy, soa_rrset.type, soa_rrset.rclass);
		int ret = knot_rdataset_copy(&copy.rrs, &soa_rrset.rrs, &pkt->mm);
		if (ret != KNOT_EOK) {
			knot_dname_free(&dname_cpy, &pkt->mm);
			return ret;
		}
		knot_rdata_t *copy_data = knot_rdataset_at(&copy.rrs, 0);
		knot_rdata_set_ttl(copy_data, min);

		flags |= KNOT_PF_FREE;
		soa_rrset = copy;
	}

	ret = process_query_put_rr(pkt, qdata, &soa_rrset, &rrsigs,
	                           KNOT_COMPR_HINT_NONE, flags);
	if (ret != KNOT_EOK && (flags & KNOT_PF_FREE)) {
		knot_rrset_clear(&soa_rrset, &pkt->mm);
	}

	return ret;
}

/*! \brief Put the delegation NS RRSet to the Authority section. */
static int put_delegation(knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Find closest delegation point. */
	while (!(qdata->node->flags & NODE_FLAGS_DELEG)) {
		qdata->node = qdata->node->parent;
	}

	/* Insert NS record. */
	knot_rrset_t rrset = node_rrset(qdata->node, KNOT_RRTYPE_NS);
	knot_rrset_t rrsigs = node_rrset(qdata->node, KNOT_RRTYPE_RRSIG);
	return process_query_put_rr(pkt, qdata, &rrset, &rrsigs,
	                            KNOT_COMPR_HINT_NONE, 0);
}

/*! \brief Put additional records for given RR. */
static int put_additional(knot_pkt_t *pkt, const knot_rrset_t *rr,
                          struct query_data *qdata, knot_rrinfo_t *info, int state)
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
		if (state != DELEG || glue->optional) {
			flags |= KNOT_PF_NOTRUNC;
		}

		uint16_t hint = knot_pkt_compr_hint(info, KNOT_COMPR_HINT_RDATA +
		                                    glue->ns_pos);
		knot_rrset_t rrsigs = node_rrset(glue->node, KNOT_RRTYPE_RRSIG);
		for (int k = 0; k < ar_type_count; ++k) {
			knot_rrset_t rrset = node_rrset(glue->node, ar_type_list[k]);
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

static int follow_cname(knot_pkt_t *pkt, uint16_t rrtype, struct query_data *qdata)
{
	const zone_node_t *cname_node = qdata->node;
	knot_rrset_t cname_rr = node_rrset(qdata->node, rrtype);
	knot_rrset_t rrsigs = node_rrset(qdata->node, KNOT_RRTYPE_RRSIG);

	assert(!knot_rrset_empty(&cname_rr));

	/* Check whether RR is already in the packet. */
	uint16_t flags = KNOT_PF_CHECKDUP;

	/* Now, try to put CNAME to answer. */
	uint16_t rr_count_before = pkt->rrset_count;
	int ret = process_query_put_rr(pkt, qdata, &cname_rr, &rrsigs, 0, flags);
	switch (ret) {
	case KNOT_EOK:    break;
	case KNOT_ESPACE: return TRUNC;
	default:          return ERROR;
	}

	/* Check if RR count increased. */
	if (pkt->rrset_count <= rr_count_before) {
		qdata->node = NULL; /* Act is if the name leads to nowhere. */
		return HIT;
	}

	/* Synthesize CNAME if followed DNAME. */
	if (rrtype == KNOT_RRTYPE_DNAME) {
		if (dname_cname_cannot_synth(&cname_rr, qdata->name)) {
			qdata->rcode = KNOT_RCODE_YXDOMAIN;
		} else {
			knot_rrset_t dname_rr = cname_rr;
			int ret = dname_cname_synth(&dname_rr, qdata->name,
			                            &cname_rr, &pkt->mm);
			if (ret != KNOT_EOK) {
				qdata->rcode = KNOT_RCODE_SERVFAIL;
				return ERROR;
			}
			ret = process_query_put_rr(pkt, qdata, &cname_rr, NULL, 0, KNOT_PF_FREE);
			switch (ret) {
			case KNOT_EOK:    break;
			case KNOT_ESPACE: return TRUNC;
			default:          return ERROR;
			}
		}
	}

	/* If node is a wildcard, follow only if we didn't visit the same node
	 * earlier, as that would mean a CNAME loop. */
	if (knot_dname_is_wildcard(cname_node->owner)) {

		/* Check if is not in wildcard nodes (loop). */
		if (wildcard_has_visited(qdata, cname_node)) {
			qdata->node = NULL; /* Act is if the name leads to nowhere. */
			return HIT;
		}

		/* Put to wildcard node list. */
		if (wildcard_visit(qdata, cname_node, qdata->previous, qdata->name) != KNOT_EOK) {
			return ERROR;
		}
	}

	/* Now follow the next CNAME TARGET. */
	qdata->name = knot_cname_name(&cname_rr.rrs);

	return FOLLOW;
}

static int name_found(knot_pkt_t *pkt, struct query_data *qdata)
{
	uint16_t qtype = knot_pkt_qtype(pkt);

	if (node_rrtype_exists(qdata->node, KNOT_RRTYPE_CNAME)
	    && qtype != KNOT_RRTYPE_CNAME
	    && qtype != KNOT_RRTYPE_RRSIG
	    && qtype != KNOT_RRTYPE_NSEC
	    && qtype != KNOT_RRTYPE_ANY) {
		return follow_cname(pkt, KNOT_RRTYPE_CNAME, qdata);
	}

	/* DS query is answered normally, but everything else at/below DP
	 * triggers referral response. */
	if (qtype != KNOT_RRTYPE_DS &&
	    ((qdata->node->flags & NODE_FLAGS_DELEG) || qdata->node->flags & NODE_FLAGS_NONAUTH)) {
		return DELEG;
	}

	uint16_t old_rrcount = pkt->rrset_count;
	int ret = put_answer(pkt, qtype, qdata);
	if (ret != KNOT_EOK) {
		if (ret == KNOT_ESPACE && (qdata->param->proc_flags & NS_QUERY_LIMIT_SIZE)) {
			return TRUNC;
		} else {
			return ERROR;
		}
	}

	/* Check for NODATA (=0 RRs added). */
	if (old_rrcount == pkt->rrset_count) {
		return NODATA;
	} else {
		return HIT;
	}
}

static int name_not_found(knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Name is covered by wildcard. */
	if (qdata->encloser->flags & NODE_FLAGS_WILDCARD_CHILD) {
		/* Find wildcard child in the zone. */
		const zone_node_t *wildcard_node =
			zone_contents_find_wildcard_child(
				qdata->zone->contents, qdata->encloser);

		qdata->node = wildcard_node;
		assert(qdata->node != NULL);

		/* Follow expanded wildcard. */
		int next_state = name_found(pkt, qdata);

		/* Put to wildcard node list. */
		if (wildcard_visit(qdata, wildcard_node, qdata->previous, qdata->name) != KNOT_EOK) {
			next_state = ERROR;
		}

		return next_state;
	}

	/* Name is under DNAME, use it for substitution. */
	knot_rrset_t dname_rrset = node_rrset(qdata->encloser, KNOT_RRTYPE_DNAME);
	if (!knot_rrset_empty(&dname_rrset)) {
		qdata->node = qdata->encloser; /* Follow encloser as new node. */
		return follow_cname(pkt, KNOT_RRTYPE_DNAME, qdata);
	}

	/* Look up an authoritative encloser or its parent. */
	const zone_node_t *node = qdata->encloser;
	while (node->rrset_count == 0 || node->flags & NODE_FLAGS_NONAUTH) {
		node = node->parent;
		assert(node);
	}

	/* Name is below delegation. */
	if ((node->flags & NODE_FLAGS_DELEG)) {
		qdata->node = node;
		return DELEG;
	}

	return MISS;
}

static int solve_name(int state, knot_pkt_t *pkt, struct query_data *qdata)
{
	int ret = zone_contents_find_dname(qdata->zone->contents, qdata->name,
	                                   &qdata->node, &qdata->encloser,
	                                   &qdata->previous);

	switch (ret) {
	case ZONE_NAME_FOUND:
		return name_found(pkt, qdata);
	case ZONE_NAME_NOT_FOUND:
		return name_not_found(pkt, qdata);
	case KNOT_EOUTOFZONE:
		assert(state == FOLLOW); /* CNAME/DNAME chain only. */
		return HIT;
	default:
		return ERROR;
	}
}

static int solve_answer(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	/* Get answer to QNAME. */
	state = solve_name(state, pkt, qdata);

	/* Is authoritative answer unless referral.
	 * Must check before we chase the CNAME chain. */
	if (state != DELEG) {
		knot_wire_set_aa(pkt->wire);
	}

	/* Additional resolving for CNAME/DNAME chain. */
	while (state == FOLLOW) {
		state = solve_name(state, pkt, qdata);
	}

	return state;
}

static int solve_answer_dnssec(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (!have_dnssec(qdata)) {
		return state; /* DNSSEC not supported. */
	}

	/* RFC4035, section 3.1 RRSIGs for RRs in ANSWER are mandatory. */
	int ret = nsec_append_rrsigs(pkt, qdata, false);
	switch (ret) {
	case KNOT_ESPACE: return TRUNC;
	case KNOT_EOK:    return state;
	default:          return ERROR;
	}
}

static int solve_authority(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	int ret = KNOT_ERROR;
	const zone_contents_t *zone_contents = qdata->zone->contents;

	switch (state) {
	case HIT:    /* Positive response. */
		ret = KNOT_EOK;
		break;
	case MISS:   /* MISS, set NXDOMAIN RCODE. */
		qdata->rcode = KNOT_RCODE_NXDOMAIN;
		ret = put_authority_soa(pkt, qdata, zone_contents);
		break;
	case NODATA: /* NODATA append AUTHORITY SOA. */
		ret = put_authority_soa(pkt, qdata, zone_contents);
		break;
	case DELEG:  /* Referral response. */
		ret = put_delegation(pkt, qdata);
		break;
	case TRUNC:  /* Truncated ANSWER. */
		ret = KNOT_ESPACE;
		break;
	case ERROR:  /* Error resolving ANSWER. */
		break;
	default:
		assert(0);
		break;
	}

	/* Evaluate final state. */
	switch (ret) {
	case KNOT_EOK:    return state; /* Keep current state. */
	case KNOT_ESPACE: return TRUNC; /* Truncated. */
	default:          return ERROR; /* Error. */
	}
}

static int solve_authority_dnssec(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (!have_dnssec(qdata)) {
		return state; /* DNSSEC not supported. */
	}

	int ret = KNOT_ERROR;

	/* Authenticated denial of existence. */
	switch (state) {
	case HIT:    ret = KNOT_EOK; break;
	case MISS:   ret = nsec_prove_nxdomain(pkt, qdata); break;
	case NODATA: ret = nsec_prove_nodata(pkt, qdata); break;
	case DELEG:  ret = nsec_prove_dp_security(pkt, qdata); break;
	case TRUNC:  ret = KNOT_ESPACE; break;
	case ERROR:  ret = KNOT_ERROR; break;
	default:
		assert(0);
		break;
	}

	/* RFC4035 3.1.3 Prove visited wildcards.
	 * Wildcard expansion applies for Name Error, Wildcard Answer and
	 * No Data proofs if at one point the search expanded a wildcard node.
	 * \note Do not attempt to prove non-authoritative data. */
	if (ret == KNOT_EOK && state != DELEG) {
		ret = nsec_prove_wildcards(pkt, qdata);
	}

	/* RFC4035, section 3.1 RRSIGs for RRs in AUTHORITY are mandatory. */
	if (ret == KNOT_EOK) {
		ret = nsec_append_rrsigs(pkt, qdata, false);
	}

	/* Evaluate final state. */
	switch (ret) {
	case KNOT_EOK:    return state; /* Keep current state. */
	case KNOT_ESPACE: return TRUNC; /* Truncated. */
	default:          return ERROR; /* Error. */
	}
}

static int solve_additional(int state, knot_pkt_t *pkt, struct query_data *qdata,
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
	case KNOT_ESPACE: return TRUNC; /* Truncated. */
	default:          return ERROR; /* Error. */
	}
}

static int solve_additional_dnssec(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (!have_dnssec(qdata)) {
		return state; /* DNSSEC not supported. */
	}

	/* RFC4035, section 3.1 RRSIGs for RRs in ADDITIONAL are optional. */
	int ret = nsec_append_rrsigs(pkt, qdata, true);
	switch(ret) {
	case KNOT_ESPACE: return TRUNC;
	case KNOT_EOK:    return state;
	default:          return ERROR;
	}
}

/*! \brief Helper for internet_query repetitive code. */
#define SOLVE_STEP(solver, state, context) \
	state = (solver)(state, pkt, qdata, context); \
	if (state == TRUNC) { \
		return KNOT_STATE_DONE; \
	} else if (state == ERROR) { \
		return KNOT_STATE_FAIL; \
	}

static int answer_query(knot_pkt_t *pkt, struct query_data *qdata)
{
	int state = BEGIN;
	struct query_plan *plan = qdata->zone->query_plan;
	struct query_plan *global_plan = conf()->query_plan;
	struct query_step *step = NULL;

	/* Resolve ANSWER. */
	knot_pkt_begin(pkt, KNOT_ANSWER);
	if (global_plan != NULL) {
		WALK_LIST(step, global_plan->stage[QPLAN_ANSWER]) {
			SOLVE_STEP(step->process, state, step->ctx);
		}
	}
	SOLVE_STEP(solve_answer, state, NULL);
	SOLVE_STEP(solve_answer_dnssec, state, NULL);
	if (plan != NULL) {
		WALK_LIST(step, plan->stage[QPLAN_ANSWER]) {
			SOLVE_STEP(step->process, state, step->ctx);
		}
	}

	/* Resolve AUTHORITY. */
	knot_pkt_begin(pkt, KNOT_AUTHORITY);
	if (global_plan != NULL) {
		WALK_LIST(step, global_plan->stage[QPLAN_AUTHORITY]) {
			SOLVE_STEP(step->process, state, step->ctx);
		}
	}
	SOLVE_STEP(solve_authority, state, NULL);
	SOLVE_STEP(solve_authority_dnssec, state, NULL);
	if (plan != NULL) {
		WALK_LIST(step, plan->stage[QPLAN_AUTHORITY]) {
			SOLVE_STEP(step->process, state, step->ctx);
		}
	}

	/* Resolve ADDITIONAL. */
	knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	if (global_plan != NULL) {
		WALK_LIST(step, global_plan->stage[QPLAN_ADDITIONAL]) {
			SOLVE_STEP(step->process, state, step->ctx);
		}
	}
	SOLVE_STEP(solve_additional, state, NULL);
	SOLVE_STEP(solve_additional_dnssec, state, NULL);
	if (plan != NULL) {
		WALK_LIST(step, plan->stage[QPLAN_ADDITIONAL]) {
			SOLVE_STEP(step->process, state, step->ctx);
		}
	}

	/* Write resulting RCODE. */
	knot_wire_set_rcode(pkt->wire, qdata->rcode);

	return KNOT_STATE_DONE;
}

int internet_process_query(knot_pkt_t *pkt, struct query_data *qdata)
{
	if (pkt == NULL || qdata == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* Check valid zone, transaction security (optional) and contents. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_REFUSED);

	/* No applicable ACL, refuse transaction security. */
	if (knot_pkt_has_tsig(qdata->query)) {
		/* We have been challenged... */
		NS_NEED_AUTH(qdata, qdata->zone->name, ACL_ACTION_NONE);

		/* Reserve space for TSIG. */
		knot_pkt_reserve(pkt, knot_tsig_wire_size(&qdata->sign.tsig_key));
	}

	NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL); /* Expired */

	/* Get answer to QNAME. */
	qdata->name = knot_pkt_qname(qdata->query);

	return answer_query(pkt, qdata);
}
