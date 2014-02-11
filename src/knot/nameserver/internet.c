#include <config.h>

#include "knot/nameserver/internet.h"
#include "knot/nameserver/nsec_proofs.h"
#include "knot/nameserver/process_query.h"
#include "libknot/common.h"
#include "libknot/rdata.h"
#include "common/debug.h"
#include "common/descriptor.h"
#include "knot/server/zones.h"

/*! \brief Query processing states. */
enum {
	BEGIN,   /* Begin name resolution. */
	NODATA,  /* Positive result with NO data. */
	HIT,     /* Positive result. */
	MISS,    /* Negative result. */
	DELEG,   /* Result is delegation. */
	FOLLOW,  /* Resolution not complete (CNAME/DNAME chain). */
	ERROR,   /* Resolution failed. */
	TRUNC    /* Finished, but truncated. */
};

/*! \brief Check if given node was already visited. */
static int wildcard_has_visited(struct query_data *qdata, const knot_node_t *node)
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
static int wildcard_visit(struct query_data *qdata, const knot_node_t *node, const knot_dname_t *sname)
{
	assert(qdata);
	assert(node);

	/* Already in the list. */
	if (wildcard_has_visited(qdata, node)) {
		return KNOT_EOK;
	}

	mm_ctx_t *mm = qdata->mm;
	struct wildcard_hit *item = mm->alloc(mm->ctx, sizeof(struct wildcard_hit));
	item->node = node;
	item->sname = sname;
	add_tail(&qdata->wildcards, (node_t *)item);
	return KNOT_EOK;
}

/*! \brief Synthetizes a CNAME RR from a DNAME. */
static knot_rrset_t *dname_cname_synth(const knot_rrset_t *dname_rr, const knot_dname_t *qname)
{
	dbg_ns("%s(%p, %p)\n", __func__, dname_rr, qname);
	knot_dname_t *owner = knot_dname_copy(qname);
	if (owner == NULL) {
		return NULL;
	}

	knot_rrset_t *cname_rrset = knot_rrset_new(owner, KNOT_RRTYPE_CNAME,
	                                           KNOT_CLASS_IN, dname_rr->ttl);
	if (cname_rrset == NULL) {
		knot_dname_free(&owner);
		return NULL;
	}

	/* Replace last labels of qname with DNAME. */
	const knot_dname_t *dname_wire = knot_rrset_owner(dname_rr);
	const knot_dname_t *dname_tgt = knot_rdata_dname_target(dname_rr);
	int labels = knot_dname_labels(dname_wire, NULL);
	knot_dname_t *cname = knot_dname_replace_suffix(qname, labels, dname_tgt);
	if (cname == NULL) {
		knot_rrset_free(&cname_rrset);
		return NULL;
	}

	/* Store DNAME into RDATA. */
	int cname_size = knot_dname_size(cname);
	uint8_t *cname_rdata = knot_rrset_create_rdata(cname_rrset, cname_size);
	if (cname_rdata == NULL) {
		knot_rrset_free(&cname_rrset);
		knot_dname_free(&cname);
		return NULL;
	}
	memcpy(cname_rdata, cname, cname_size);
	knot_dname_free(&cname);

	return cname_rrset;
}

/*!
 * \brief Checks if the name created by replacing the owner of \a dname_rrset
 *        in the \a qname by the DNAME's target would be longer than allowed.
 */
static bool dname_cname_cannot_synth(const knot_rrset_t *rrset, const knot_dname_t *qname)
{
	if (knot_dname_labels(qname, NULL)
		- knot_dname_labels(knot_rrset_owner(rrset), NULL)
		+ knot_dname_labels(knot_rdata_dname_target(rrset), NULL)
		> KNOT_DNAME_MAXLABELS) {
		return true;
	} else {
		return false;
	}
}

/*! \brief DNSSEC both requested & available. */
static bool have_dnssec(struct query_data *qdata)
{
	return knot_pkt_have_dnssec(qdata->query) &&
	       knot_zone_contents_is_signed(qdata->zone->contents);
}

/*! \brief Put RR into packet, expand wildcards. */
static int put_rr(knot_pkt_t *pkt, const knot_rrset_t *rr, uint16_t compr_hint,
		  uint32_t flags, struct query_data *qdata)
{
	/* RFC3123 s.6 - empty APL is valid, ignore other empty RRs. */
	if (knot_rrset_rdata_rr_count(rr) < 1 &&
	    knot_rrset_type(rr) != KNOT_RRTYPE_APL) {
		dbg_ns("%s: refusing to put empty RR of type %u\n", __func__, knot_rrset_type(rr));
		return KNOT_EMALF;
	}

	/* If we already have compressed name on the wire and compression hint,
	 * we can just insert RRSet and fake synthesis by using compression
	 * hint. */
	int ret = KNOT_EOK;
	if (compr_hint == COMPR_HINT_NONE && knot_dname_is_wildcard(rr->owner)) {
		ret = knot_rrset_deep_copy(rr, (knot_rrset_t **)&rr);
		if (ret != KNOT_EOK) {
			return KNOT_ENOMEM;
		}

		knot_rrset_set_owner((knot_rrset_t *)rr, qdata->name);
		flags |= KNOT_PF_FREE;
	}

	ret = knot_pkt_put(pkt, compr_hint, rr, flags);
	if (ret != KNOT_EOK && (flags & KNOT_PF_FREE)) {
		knot_rrset_deep_free((knot_rrset_t **)&rr, 1);
	}

	return ret;
}

/*! \brief This is a wildcard-covered or any other terminal node for QNAME.
 *         e.g. positive answer.
 */
static int put_answer(knot_pkt_t *pkt, uint16_t type, struct query_data *qdata)
{
	const knot_rrset_t *rrset = NULL;
	knot_rrset_t **rrsets = knot_node_get_rrsets_no_copy(qdata->node);

	/* Wildcard expansion or exact match, either way RRSet owner is
	 * is QNAME. We can fake name synthesis by setting compression hint to
	 * QNAME position. Just need to check if we're answering QNAME and not
	 * a CNAME target.
	 */
	uint16_t compr_hint = COMPR_HINT_NONE;
	if (pkt->rrset_count == 0) { /* Guaranteed first answer. */
		compr_hint = COMPR_HINT_QNAME;
	}

	int ret = KNOT_EOK;
	switch (type) {
	case KNOT_RRTYPE_ANY: /* Append all RRSets. */
		/* If ANY not allowed, set TC bit. */
		if ((qdata->param->proc_flags & NS_QUERY_LIMIT_ANY) &&
		    (qdata->zone->conf->disable_any)) {
			dbg_ns("%s: ANY/UDP disabled for this zone TC=1\n", __func__);
			knot_wire_set_tc(pkt->wire);
			return KNOT_ESPACE;
		}
		for (unsigned i = 0; i < knot_node_rrset_count(qdata->node); ++i) {
			ret = put_rr(pkt, rrsets[i], compr_hint, 0, qdata);
			if (ret != KNOT_EOK) {
				break;
			}
		}
		break;
	case KNOT_RRTYPE_RRSIG: /* Append all RRSIGs. */
		for (unsigned i = 0; i < knot_node_rrset_count(qdata->node); ++i) {
			if (rrsets[i]->rrsigs) {
				ret = put_rr(pkt, rrsets[i]->rrsigs, compr_hint, 0, qdata);
				if (ret != KNOT_EOK) {
					break;
				}
			}
		}
		break;
	default: /* Single RRSet of given type. */
		rrset = knot_node_get_rrset(qdata->node, type);
		if (rrset) {
			ret = put_rr(pkt, rrset, compr_hint, 0, qdata);
		}
		break;
	}

	return ret;
}

/*! \brief Puts optional NS RRSet to the Authority section of the response. */
static int put_authority_ns(knot_pkt_t *pkt, struct query_data *qdata)
{
	const knot_zone_contents_t *zone = qdata->zone->contents;
	dbg_ns("%s(%p, %p)\n", __func__, pkt, qdata);

	/* DS/DNSKEY queries are not referrals. NS is optional.
	 * But taking response size into consideration, DS/DNSKEY RRs
	 * are rather large and may trigger fragmentation or even TCP
	 * recovery. */
	uint16_t query_type = knot_pkt_qtype(pkt);
	if (query_type == KNOT_RRTYPE_DS     || /* Too large response */
	    query_type == KNOT_RRTYPE_DNSKEY || /* Too large response */
	    qdata->node == NULL /* CNAME leading to non-existent name.*/ ) {
		dbg_ns("%s: not adding AUTHORITY NS for this response\n", __func__);
		return KNOT_EOK;
	}

	const knot_rrset_t *ns_rrset = knot_node_rrset(zone->apex, KNOT_RRTYPE_NS);
	if (ns_rrset) {
		return knot_pkt_put(pkt, 0, ns_rrset, KNOT_PF_NOTRUNC|KNOT_PF_CHECKDUP);
	} else {
		dbg_ns("%s: no NS RRSets in this zone, fishy...\n", __func__);
	}
	return KNOT_EOK;
}

/*! \brief Puts optional SOA RRSet to the Authority section of the response. */
static int put_authority_soa(knot_pkt_t *pkt, const knot_zone_contents_t *zone)
{
	dbg_ns("%s(%p, %p)\n", __func__, pkt, zone);
	knot_rrset_t *soa_rrset = knot_node_get_rrset(zone->apex, KNOT_RRTYPE_SOA);
	assert(soa_rrset);

	// if SOA's TTL is larger than MINIMUM, copy the RRSet and set
	// MINIMUM as TTL
	int ret = KNOT_EOK;
	uint32_t flags = KNOT_PF_NOTRUNC;
	uint32_t min = knot_rdata_soa_minimum(soa_rrset);
	if (min < knot_rrset_ttl(soa_rrset)) {
		ret = knot_rrset_deep_copy(soa_rrset, &soa_rrset);
		if (ret != KNOT_EOK) {
			return ret;
		}

		knot_rrset_set_ttl(soa_rrset, min);
		flags |= KNOT_PF_FREE;
	}

	ret = knot_pkt_put(pkt, 0, soa_rrset, flags);
	if (ret != KNOT_EOK && (flags & KNOT_PF_FREE)) {
		knot_rrset_deep_free(&soa_rrset, 1);
	}

	return ret;
}

/*! \brief Put the delegation NS RRSet to the Authority section. */
static int put_delegation(knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Find closest delegation point. */
	while (!knot_node_is_deleg_point(qdata->node)) {
		qdata->node = knot_node_parent(qdata->node);
	}

	/* Insert NS record. */
	const knot_rrset_t *rrset = knot_node_rrset(qdata->node, KNOT_RRTYPE_NS);
	return knot_pkt_put(pkt, 0, rrset, 0);
}

/*! \brief Put additional records for given RR. */
static int put_additional(knot_pkt_t *pkt, const knot_rrset_t *rr, knot_rrinfo_t *info)
{
	/* Valid types for ADDITIONALS insertion. */
	/* \note Not resolving CNAMEs as MX/NS name must not be an alias. (RFC2181/10.3) */
	static const uint16_t ar_type_list[] = {KNOT_RRTYPE_A, KNOT_RRTYPE_AAAA};
	static const int ar_type_count = 2;

	int ret = KNOT_EOK;
	uint32_t flags = KNOT_PF_NOTRUNC|KNOT_PF_CHECKDUP;
	uint16_t hint = COMPR_HINT_NONE;
	const knot_node_t *node = NULL;
	const knot_rrset_t *additional = NULL;

	/* All RRs should have additional node cached or NULL. */
	for (uint16_t i = 0; i < rr->rdata_count; i++) {
		hint = knot_pkt_compr_hint(info, COMPR_HINT_RDATA + i);
		node = rr->additional[i];

		/* No additional node for this record. */
		if (node == NULL) {
			continue;
		}

		for (int k = 0; k < ar_type_count; ++k) {
			additional = knot_node_rrset(node, ar_type_list[k]);
			if (additional == NULL) {
				continue;
			}
			ret = knot_pkt_put(pkt, hint, additional, flags);
			if (ret != KNOT_EOK) {
				break;
			}
		}
	}

	return ret;
}

static int follow_cname(knot_pkt_t *pkt, uint16_t rrtype, struct query_data *qdata)
{
	dbg_ns("%s(%p, %p)\n", __func__, pkt, qdata);

	const knot_node_t *cname_node = qdata->node;
	knot_rrset_t *cname_rr = knot_node_get_rrset(qdata->node, rrtype);
	int ret = KNOT_EOK;

	assert(cname_rr != NULL);

	/* Check whether RR is already in the packet. */
	uint16_t flags = KNOT_PF_CHECKDUP;

	/* Now, try to put CNAME to answer. */
	uint16_t rr_count_before = pkt->rrset_count;
	ret = put_rr(pkt, cname_rr, 0, flags, qdata);
	switch (ret) {
	case KNOT_EOK:    break;
	case KNOT_ESPACE: return TRUNC;
	default:          return ERROR;
	}

	/* Check if RR count increased. */
	if (pkt->rrset_count <= rr_count_before) {
		dbg_ns("%s: RR %p already inserted => CNAME loop\n",
		       __func__, cname_rr);
		qdata->node = NULL; /* Act is if the name leads to nowhere. */
		return HIT;
	}

	/* Synthesize CNAME if followed DNAME. */
	if (rrtype == KNOT_RRTYPE_DNAME) {
		if (dname_cname_cannot_synth(cname_rr, qdata->name)) {
			qdata->rcode = KNOT_RCODE_YXDOMAIN;
			return ERROR;
		}
		cname_rr = dname_cname_synth(cname_rr, qdata->name);
		ret = put_rr(pkt, cname_rr, 0, KNOT_PF_FREE, qdata);
		switch (ret) {
		case KNOT_EOK:    break;
		case KNOT_ESPACE: return TRUNC;
		default:          return ERROR;
		}
	}

	/* If node is a wildcard, follow only if we didn't visit the same node
	 * earlier, as that would mean a CNAME loop. */
	if (knot_dname_is_wildcard(cname_node->owner)) {

		/* Check if is not in wildcard nodes (loop). */
		dbg_ns("%s: CNAME node %p is wildcard\n", __func__, cname_node);
		if (wildcard_has_visited(qdata, cname_node)) {
			dbg_ns("%s: node %p already visited => CNAME loop\n",
			       __func__, cname_node);
			qdata->node = NULL; /* Act is if the name leads to nowhere. */
			return HIT;
		}

		/* Put to wildcard node list. */
		if (wildcard_visit(qdata, cname_node, qdata->name) != KNOT_EOK) {
			return ERROR;
		}
	}

	/* Now follow the next CNAME TARGET. */
	qdata->name = knot_rdata_cname_name(cname_rr);

#ifdef KNOT_NS_DEBUG
	char *cname_str = knot_dname_to_str(cname_node->owner);
	char *target_str = knot_dname_to_str(qdata->name);
	dbg_ns("%s: FOLLOW '%s' -> '%s'\n", __func__, cname_str, target_str);
	free(cname_str);
	free(target_str);
#endif /* KNOT_NS_DEBUG */

	return FOLLOW;
}

static int name_found(knot_pkt_t *pkt, struct query_data *qdata)
{
	uint16_t qtype = knot_pkt_qtype(pkt);
	dbg_ns("%s(%p, %p)\n", __func__, pkt, qdata);

	if (knot_node_rrset(qdata->node, KNOT_RRTYPE_CNAME) != NULL
	    && qtype != KNOT_RRTYPE_CNAME
	    && qtype != KNOT_RRTYPE_RRSIG
	    && qtype != KNOT_RRTYPE_ANY) {
		dbg_ns("%s: solving CNAME\n", __func__);
		return follow_cname(pkt, KNOT_RRTYPE_CNAME, qdata);
	}

	/* DS query is answered normally, but everything else at/below DP
	 * triggers referral response. */
	if (qtype != KNOT_RRTYPE_DS &&
	    (knot_node_is_deleg_point(qdata->node) || knot_node_is_non_auth(qdata->node))) {
		dbg_ns("%s: solving REFERRAL\n", __func__);
		return DELEG;
	}

	uint16_t old_rrcount = pkt->rrset_count;
	int ret = put_answer(pkt, qtype, qdata);
	if (ret != KNOT_EOK) {
		dbg_ns("%s: failed answer from node %p (%s)\n",
		       __func__, qdata->node, knot_strerror(ret));
		if (ret == KNOT_ESPACE) {
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
	dbg_ns("%s(%p, %p)\n", __func__, pkt, qdata);

	/* Name is covered by wildcard. */
	const knot_node_t *wildcard_node = knot_node_wildcard_child(qdata->encloser);
	if (wildcard_node) {
		dbg_ns("%s: name %p covered by wildcard\n", __func__, qdata->name);
		qdata->node = wildcard_node;
		/* keep encloser */
		qdata->previous = NULL;

		/* Follow expanded wildcard. */
		int next_state = name_found(pkt, qdata);

		/* Put to wildcard node list. */
		if (wildcard_visit(qdata, wildcard_node, qdata->name) != KNOT_EOK) {
				next_state = ERROR;
		}

		return next_state;
	}

	/* Name is under DNAME, use it for substitution. */
	knot_rrset_t *dname_rrset = knot_node_get_rrset(qdata->encloser, KNOT_RRTYPE_DNAME);
	if (dname_rrset != NULL
	    && knot_rrset_rdata_rr_count(dname_rrset) > 0) {
		dbg_ns("%s: solving DNAME for name %p\n", __func__, qdata->name);
		qdata->node = qdata->encloser; /* Follow encloser as new node. */
		return follow_cname(pkt, KNOT_RRTYPE_DNAME, qdata);
	}

	/* Name is below delegation. */
	if (knot_node_is_deleg_point(qdata->encloser)) {
		dbg_ns("%s: name below delegation point %p\n", __func__, qdata->name);
		qdata->node = qdata->encloser;
		return DELEG;
	}

	dbg_ns("%s: name not found in zone %p\n", __func__, qdata->name);
	return MISS;
}

static int solve_name(int state, knot_pkt_t *pkt, struct query_data *qdata)
{
	dbg_ns("%s(%d, %p, %p)\n", __func__, state, pkt, qdata);
	int ret = knot_zone_contents_find_dname(qdata->zone->contents, qdata->name,
	                                        &qdata->node, &qdata->encloser,
	                                        &qdata->previous);

	switch(ret) {
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

static int solve_answer_section(int state, knot_pkt_t *pkt, struct query_data *qdata)
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

static int solve_answer_dnssec(int state, knot_pkt_t *pkt, struct query_data *qdata)
{
	if (!have_dnssec(qdata)) {
		return state; /* DNSSEC not supported. */
	}

	/* RFC4035, section 3.1 RRSIGs for RRs in ANSWER are mandatory. */
	int ret = nsec_append_rrsigs(pkt, false);
	switch(ret) {
	case KNOT_ESPACE: return TRUNC;
	case KNOT_EOK:    return state;
	default:          return ERROR;
	}
}

static int solve_authority(int state, knot_pkt_t *pkt, struct query_data *qdata)
{
	int ret = KNOT_ERROR;
	const knot_zone_contents_t *zone_contents = qdata->zone->contents;

	switch (state) {
	case HIT:    /* Positive response, add (optional) AUTHORITY NS. */
		dbg_ns("%s: answer is POSITIVE\n", __func__);
		ret = put_authority_ns(pkt, qdata);
		break;
	case MISS:   /* MISS, set NXDOMAIN RCODE. */
		dbg_ns("%s: answer is NXDOMAIN\n", __func__);
		qdata->rcode = KNOT_RCODE_NXDOMAIN;
		ret = put_authority_soa(pkt, zone_contents);
		break;
	case NODATA: /* NODATA append AUTHORITY SOA. */
		dbg_ns("%s: answer is NODATA\n", __func__);
		ret = put_authority_soa(pkt, zone_contents);
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

static int solve_authority_dnssec(int state, knot_pkt_t *pkt, struct query_data *qdata)
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
	 * No Data proofs if at one point the search expanded a wildcard node. */
	if (ret == KNOT_EOK) {
		ret = nsec_prove_wildcards(pkt, qdata);
	}

	/* RFC4035, section 3.1 RRSIGs for RRs in AUTHORITY are mandatory. */
	if (ret == KNOT_EOK) {
		ret = nsec_append_rrsigs(pkt, false);
	}

	/* Evaluate final state. */
	switch (ret) {
	case KNOT_EOK:    return state; /* Keep current state. */
	case KNOT_ESPACE: return TRUNC; /* Truncated. */
	default:          return ERROR; /* Error. */
	}
}

static int solve_additional(int state, knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Put OPT RR. */
	int ret = knot_pkt_put_opt(pkt);

	/* Scan all RRs in ANSWER/AUTHORITY. */
	for (uint16_t i = 0; i < pkt->rrset_count; ++i) {
		/* Skip types for which it doesn't apply. */
		if (!rrset_additional_needed(pkt->rr[i]->type)) {
			continue;
		}
		/* Put additional records for given type. */
		ret = put_additional(pkt, pkt->rr[i], &pkt->rr_info[i]);
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

static int solve_additional_dnssec(int state, knot_pkt_t *pkt, struct query_data *qdata)
{
	if (!have_dnssec(qdata)) {
		return state; /* DNSSEC not supported. */
	}

	/* RFC4035, section 3.1 RRSIGs for RRs in ADDITIONAL are optional. */
	int ret = nsec_append_rrsigs(pkt, true);
	switch(ret) {
	case KNOT_ESPACE: return TRUNC;
	case KNOT_EOK:    return state;
	default:          return ERROR;
	}
}

/*! \brief Helper for internet_answer repetitive code. */
#define SOLVE_STEP(solver, state) \
	state = solver(state, response, qdata); \
	if (state == TRUNC) { \
		return NS_PROC_DONE; \
	} else if (state == ERROR) { \
		return NS_PROC_FAIL; \
	}

int internet_answer(knot_pkt_t *response, struct query_data *qdata)
{
	dbg_ns("%s(%p, %p)\n", __func__, response, qdata);
	if (response == NULL || qdata == NULL) {
		return NS_PROC_FAIL;
	}

	/* Check valid zone, transaction security (optional) and contents. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_REFUSED);

	/* No applicable ACL, refuse transaction security. */
	if (knot_pkt_have_tsig(qdata->query)) {
		/* We have been challenged... */
		NS_NEED_AUTH(qdata->zone->xfr_out, qdata);

		/* Reserve space for TSIG. */
		knot_pkt_reserve(response, tsig_wire_maxsize(qdata->sign.tsig_key));
	}

	NS_NEED_ZONE_CONTENTS(qdata, KNOT_RCODE_SERVFAIL); /* Expired */

	/* Get answer to QNAME. */
	dbg_ns("%s: writing %p ANSWER\n", __func__, response);
	knot_pkt_begin(response, KNOT_ANSWER);
	qdata->name = knot_pkt_qname(qdata->query);

	/* Begin processing. */
	int state = BEGIN;
	SOLVE_STEP(solve_answer_section, state);
	SOLVE_STEP(solve_answer_dnssec, state);

	/* Resolve AUTHORITY. */
	dbg_ns("%s: writing %p AUTHORITY\n", __func__, response);
	knot_pkt_begin(response, KNOT_AUTHORITY);
	SOLVE_STEP(solve_authority, state);
	SOLVE_STEP(solve_authority_dnssec, state);

	/* Resolve ADDITIONAL. */
	dbg_ns("%s: writing %p ADDITIONAL\n", __func__, response);
	knot_pkt_begin(response, KNOT_ADDITIONAL);
	SOLVE_STEP(solve_additional, state);
	SOLVE_STEP(solve_additional_dnssec, state);

	/* Write resulting RCODE. */
	knot_wire_set_rcode(response->wire, qdata->rcode);

	/* Complete response. */
	return NS_PROC_DONE;
}

#undef SOLVE_STEP
