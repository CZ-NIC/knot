
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
static int dname_cname_synth(const knot_rrset_t *dname_rr,
                             const knot_dname_t *qname,
                             knot_rrset_t *cname_rrset,
                             mm_ctx_t *mm)
{
	if (cname_rrset == NULL) {
		return KNOT_EINVAL;
	}
	dbg_ns("%s(%p, %p)\n", __func__, dname_rr, qname);
	
	cname_rrset->owner = knot_dname_copy(qname, mm);
	if (cname_rrset->owner == NULL) {
		return KNOT_ENOMEM;
	}
	cname_rrset->type = KNOT_RRTYPE_CNAME;
	cname_rrset->rclass = KNOT_CLASS_IN;
	knot_rrs_init(&cname_rrset->rrs);

	/* Replace last labels of qname with DNAME. */
	const knot_dname_t *dname_wire = dname_rr->owner;
	const knot_dname_t *dname_tgt = knot_rrs_dname_target(&dname_rr->rrs);
	int labels = knot_dname_labels(dname_wire, NULL);
	knot_dname_t *cname = knot_dname_replace_suffix(qname, labels, dname_tgt);
	if (cname == NULL) {
		return KNOT_ENOMEM;
	}

	/* Store DNAME into RDATA. */
	int cname_size = knot_dname_size(cname);
	uint8_t cname_rdata[cname_size];
	memcpy(cname_rdata, cname, cname_size);
	knot_dname_free(&cname, NULL);

	return knot_rrset_add_rr(cname_rrset, cname_rdata, cname_size,
	                         knot_rrset_rr_ttl(dname_rr, 0), mm);
}

/*!
 * \brief Checks if the name created by replacing the owner of \a dname_rrset
 *        in the \a qname by the DNAME's target would be longer than allowed.
 */
static bool dname_cname_cannot_synth(const knot_rrset_t *rrset, const knot_dname_t *qname)
{
	if (knot_dname_labels(qname, NULL)
		- knot_dname_labels(rrset->owner, NULL)
		+ knot_dname_labels(knot_rrs_dname_target(&rrset->rrs), NULL)
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

/*! \brief Synthesize RRSIG for given parameters, store in 'qdata' for later use */
static int put_rrsig(const knot_dname_t *sig_owner, uint16_t type,
                     const knot_rrset_t *rrsigs,
                     knot_rrinfo_t *rrinfo,
                     struct query_data *qdata)
{
	knot_rrset_t synth_sig;
	knot_rrs_init(&synth_sig.rrs);
	int ret = knot_rrs_synth_rrsig(type, &rrsigs->rrs,
	                               &synth_sig.rrs, qdata->mm);
	if (ret == KNOT_ENOENT) {
		// No signature
		return KNOT_EOK;
	}
	if (ret != KNOT_EOK) {
		return ret;
	}
	synth_sig.owner = knot_dname_copy(sig_owner, qdata->mm);
	if (synth_sig.owner == NULL) {
		knot_rrs_clear(&synth_sig.rrs, qdata->mm);
	}
	synth_sig.type = KNOT_RRTYPE_RRSIG;
	synth_sig.rclass = KNOT_CLASS_IN;
	synth_sig.additional = NULL;
	struct rrsig_info *info = mm_alloc(qdata->mm, sizeof(struct rrsig_info));
	if (info == NULL) {
		ERR_ALLOC_FAILED;
		knot_dname_free(&synth_sig.owner, qdata->mm);
		knot_rrs_clear(&synth_sig.rrs, qdata->mm);
		return KNOT_ENOMEM;
	}
	info->synth_rrsig = synth_sig;
	info->rrinfo = rrinfo;
	add_tail(&qdata->rrsigs, &info->n);

	return KNOT_EOK;
}

/*! \brief This is a wildcard-covered or any other terminal node for QNAME.
 *         e.g. positive answer.
 */
static int put_answer(knot_pkt_t *pkt, uint16_t type, struct query_data *qdata)
{
	knot_rrset_t rrset = { 0 };

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
	case KNOT_RRTYPE_ANY: /* Append all RRSets. */ {
		/* If ANY not allowed, set TC bit. */
		if ((qdata->param->proc_flags & NS_QUERY_LIMIT_ANY) &&
		    (qdata->zone->conf->disable_any)) {
			dbg_ns("%s: ANY/UDP disabled for this zone TC=1\n", __func__);
			knot_wire_set_tc(pkt->wire);
			return KNOT_ESPACE;
		}
		for (unsigned i = 0; i < knot_node_rrset_count(qdata->node); ++i) {
			knot_node_fill_rrset_pos(qdata->node, i, &rrset);
			ret = ns_put_rr(pkt, &rrset, NULL, compr_hint, 0, qdata);
			if (ret != KNOT_EOK) {
				break;
			}
		}
		break;
	}
	default: /* Single RRSet of given type. */
		knot_node_fill_rrset(qdata->node, type, &rrset);
		if (!knot_rrset_empty(&rrset)) {
			knot_rrset_t rrsigs = RRSET_INIT(qdata->node, KNOT_RRTYPE_RRSIG);
			ret = ns_put_rr(pkt, &rrset, &rrsigs, compr_hint, 0, qdata);
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

	knot_rrset_t ns_rrset = RRSET_INIT(zone->apex, KNOT_RRTYPE_NS);
	if (!knot_rrset_empty(&ns_rrset)) {
		knot_rrset_t rrsigs = RRSET_INIT(zone->apex, KNOT_RRTYPE_RRSIG);
		return ns_put_rr(pkt, &ns_rrset, &rrsigs, COMPR_HINT_NONE,
		                 KNOT_PF_NOTRUNC|KNOT_PF_CHECKDUP, qdata);
	} else {
		dbg_ns("%s: no NS RRSets in this zone, fishy...\n", __func__);
	}
	return KNOT_EOK;
}

/*! \brief Puts optional SOA RRSet to the Authority section of the response. */
static int put_authority_soa(knot_pkt_t *pkt, struct query_data *qdata,
                             const knot_zone_contents_t *zone)
{
	dbg_ns("%s(%p, %p)\n", __func__, pkt, zone);
	knot_rrset_t soa_rrset = RRSET_INIT(zone->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t rrsigs = RRSET_INIT(zone->apex, KNOT_RRTYPE_RRSIG);

	// if SOA's TTL is larger than MINIMUM, copy the RRSet and set
	// MINIMUM as TTL
	int ret = KNOT_EOK;
	uint32_t flags = KNOT_PF_NOTRUNC;
	uint32_t min = knot_rrs_soa_minimum(&soa_rrset.rrs);
	if (min < knot_rrset_rr_ttl(&soa_rrset, 0)) {
		knot_rrset_t copy;
		ret = knot_rrset_copy_int(&copy, &soa_rrset, &pkt->mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
		knot_rrset_rr_set_ttl(&soa_rrset, 0, min);
		
		flags |= KNOT_PF_FREE;
		soa_rrset = copy;
	}

	ret = ns_put_rr(pkt, &soa_rrset, &rrsigs, COMPR_HINT_NONE, flags, qdata);
	if (ret != KNOT_EOK && (flags & KNOT_PF_FREE)) {
		knot_dname_free(&soa_rrset.owner, &pkt->mm);
		knot_rrs_clear(&soa_rrset.rrs, &pkt->mm);
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
	knot_rrset_t rrset = RRSET_INIT(qdata->node, KNOT_RRTYPE_NS);
	knot_rrset_t rrsigs = RRSET_INIT(qdata->node, KNOT_RRTYPE_RRSIG);
	return ns_put_rr(pkt, &rrset, &rrsigs, COMPR_HINT_NONE, 0, qdata);
}

/*! \brief Put additional records for given RR. */
static int put_additional(knot_pkt_t *pkt, const knot_rrset_t *rr,
                          struct query_data *qdata, knot_rrinfo_t *info)
{
	/* Valid types for ADDITIONALS insertion. */
	/* \note Not resolving CNAMEs as MX/NS name must not be an alias. (RFC2181/10.3) */
	static const uint16_t ar_type_list[] = {KNOT_RRTYPE_A, KNOT_RRTYPE_AAAA};
	static const int ar_type_count = 2;

	int ret = KNOT_EOK;
	uint32_t flags = KNOT_PF_NOTRUNC|KNOT_PF_CHECKDUP;
	uint16_t hint = COMPR_HINT_NONE;
	const knot_node_t *node = NULL;

	/* All RRs should have additional node cached or NULL. */
	uint16_t rr_rdata_count = knot_rrset_rr_count(rr);
	for (uint16_t i = 0; i < rr_rdata_count; i++) {
		hint = knot_pkt_compr_hint(info, COMPR_HINT_RDATA + i);
		node = rr->additional[i];
		
		/* No additional node for this record. */
		if (node == NULL) {
			continue;
		}
		
		knot_rrset_t rrsigs = RRSET_INIT(node, KNOT_RRTYPE_RRSIG);
		for (int k = 0; k < ar_type_count; ++k) {
			knot_rrset_t additional = RRSET_INIT(node, ar_type_list[k]);
			if (knot_rrset_empty(&additional)) {
				continue;
			}
			ret = ns_put_rr(pkt, &additional, &rrsigs,
			                hint, flags, qdata);
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
	knot_rrset_t cname_rr = RRSET_INIT(qdata->node, rrtype);
	knot_rrset_t rrsigs = RRSET_INIT(qdata->node, KNOT_RRTYPE_RRSIG);
	int ret = KNOT_EOK;

	assert(!knot_rrset_empty(&cname_rr));

	/* Check whether RR is already in the packet. */
	uint16_t flags = KNOT_PF_CHECKDUP;

	/* Now, try to put CNAME to answer. */
	uint16_t rr_count_before = pkt->rrset_count;
	ret = ns_put_rr(pkt, &cname_rr, &rrsigs, 0, flags, qdata);
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
		if (dname_cname_cannot_synth(&cname_rr, qdata->name)) {
			qdata->rcode = KNOT_RCODE_YXDOMAIN;
			return ERROR;
		}
		knot_rrset_t dname_rr = cname_rr;
		ret = dname_cname_synth(&dname_rr, qdata->name, &cname_rr,
		                        &pkt->mm);
		if (ret != KNOT_EOK) {
			qdata->rcode = KNOT_RCODE_SERVFAIL;
			return ERROR;
		}
		ret = ns_put_rr(pkt, &cname_rr, NULL, 0, KNOT_PF_FREE, qdata);
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
	qdata->name = knot_rrs_cname_name(&cname_rr.rrs);

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

	if (knot_node_rrtype_exists(qdata->node, KNOT_RRTYPE_CNAME)
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
	knot_rrset_t dname_rrset = RRSET_INIT(qdata->encloser, KNOT_RRTYPE_DNAME);
	if (!knot_rrset_empty(&dname_rrset)) {
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
	int ret = nsec_append_rrsigs(pkt, qdata, false);
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
		ret = put_authority_soa(pkt, qdata, zone_contents);
		break;
	case NODATA: /* NODATA append AUTHORITY SOA. */
		dbg_ns("%s: answer is NODATA\n", __func__);
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

static int solve_additional(int state, knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Put OPT RR. */
	int ret = knot_pkt_put_opt(pkt);

	/* Scan all RRs in ANSWER/AUTHORITY. */
	for (uint16_t i = 0; i < pkt->rrset_count; ++i) {
		/* Skip types for which it doesn't apply. */
		if (!rrset_additional_needed(pkt->rr[i].type)) {
			continue;
		}
		/* Put additional records for given type. */
		ret = put_additional(pkt, &pkt->rr[i], qdata, &pkt->rr_info[i]);
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
	int ret = nsec_append_rrsigs(pkt, qdata, true);
	switch(ret) {
	case KNOT_ESPACE: return TRUNC;
	case KNOT_EOK:    return state;
	default:          return ERROR;
	}
}

int ns_put_rr(knot_pkt_t *pkt, knot_rrset_t *rr,
              knot_rrset_t *rrsigs, uint16_t compr_hint,
              uint32_t flags, struct query_data *qdata)
{
	/* RFC3123 s.6 - empty APL is valid, ignore other empty RRs. */
	if (knot_rrset_rr_count(rr) < 1 &&
	    rr->type != KNOT_RRTYPE_APL) {
		dbg_ns("%s: refusing to put empty RR of type %u\n", __func__, rr->type);
		return KNOT_EMALF;
	}

	/* Wildcard expansion applies only for answers. */
	bool expand = false;
	if (pkt->current == KNOT_ANSWER) {
		/* Expand if RR is wildcard & we didn't query for wildcard. */
		expand = (knot_dname_is_wildcard(rr->owner) && !knot_dname_is_wildcard(qdata->name));
	}

	/* If we already have compressed name on the wire and compression hint,
	 * we can just insert RRSet and fake synthesis by using compression
	 * hint. */
	int ret = KNOT_EOK;
	if (compr_hint == COMPR_HINT_NONE && expand) {
		rr->owner = (knot_dname_t *)qdata->name;
		knot_rrset_t copy;
		int ret = knot_rrset_copy_int(&copy, rr, &pkt->mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
		flags |= KNOT_PF_FREE;
		*rr = copy;
	}

	uint16_t prev_count = pkt->rrset_count;
	ret = knot_pkt_put(pkt, compr_hint, rr, flags);
	if (ret != KNOT_EOK) {
		knot_dname_free(&rr->owner, &pkt->mm);
		knot_rrs_clear(&rr->rrs, &pkt->mm);
		return ret;
	}

	bool inserted = (prev_count != pkt->rrset_count);
	if (inserted &&
	    !knot_rrset_empty(rrsigs) && rr->type != KNOT_RRTYPE_RRSIG) {
		// Get rrinfo of just inserted RR.
		knot_rrinfo_t *rrinfo = &pkt->rr_info[pkt->rrset_count - 1];
		ret = put_rrsig(rr->owner, rr->type, rrsigs, rrinfo, qdata);
	}

	return ret;
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
