#include <config.h>

#include "libknot/nameserver/internet.h"
#include "libknot/nameserver/ns_proc_query.h"
#include "libknot/common.h"
#include "libknot/rdata.h"
#include "libknot/util/debug.h"
#include "common/descriptor.h"
#include "common/acl.h"
#include "common/evsched.h"

/*! \todo I think I should move all dns-auth-server specific stuff
 *        close to server and leave only generic stuff in libknot.
 *        I'll do that when I finish.
 */
#include "knot/server/zones.h"

/* Visited wildcard node list. */
struct wildcard_hit {
	node_t n;
	const knot_node_t *node;
	const knot_dname_t *sname;
};

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

/*! \brief Features. */
enum {
	HAVE_DNSSEC = 1 << 0 /* DNSSEC both requested and supported. */
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

	mm_ctx_t *mm = qdata->mm;
	struct wildcard_hit *item = mm->alloc(mm->ctx, sizeof(struct wildcard_hit));
	item->node = node;
	item->sname = sname;
	add_tail(&qdata->wildcards, (node_t *)item);
	return KNOT_EOK;
}

/*! \brief Put all covering records for wildcard list. */
static int wildcard_list_cover(knot_pkt_t *pkt, struct query_data *qdata)
{
	int ret = KNOT_EOK;
	struct wildcard_hit *item = NULL;

	WALK_LIST(item, qdata->wildcards) {
		ret = ns_put_nsec_nsec3_wildcard_answer(
					item->node,
					knot_node_parent(item->node),
					NULL, qdata->zone->contents,
					item->sname,
					pkt);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	return ret;
}


/*! \brief Synthetizes a CNAME RR from a DNAME. */
static knot_rrset_t *dname_cname_synth(const knot_rrset_t *dname_rr, const knot_dname_t *qname)
{
	dbg_ns("%s(%p, %p)\n", __func__, dname_rr, qname);
	knot_dname_t *owner = knot_dname_copy(qname);
	if (owner == NULL) {
		return NULL;
	}

	knot_rrset_t *cname_rrset = knot_rrset_new(
					    owner, KNOT_RRTYPE_CNAME, KNOT_CLASS_IN, dname_rr->ttl);
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
static bool dname_cname_can_synth(const knot_rrset_t *rrset, const knot_dname_t *qname)
{
	if (knot_dname_labels(qname, NULL)
		- knot_dname_labels(knot_rrset_owner(rrset), NULL)
		+ knot_dname_labels(knot_rdata_dname_target(rrset), NULL)
		> KNOT_DNAME_MAXLEN) {
		return true;
	} else {
		return false;
	}
}

/*! \brief DNSSEC both requested & available. */
static bool have_dnssec(struct query_data *qdata)
{
	return qdata->flags & HAVE_DNSSEC;
}

/*! \brief Put RR into packet, expand wildcards. */
static int put_rr(knot_pkt_t *pkt, const knot_rrset_t *rr, uint16_t compr_hint,
		  uint32_t flags, struct query_data *qdata)
{
	/* RFC3123 s.6 - empty APL is valid, ignore other empty RRs. */
	if (knot_rrset_rdata_rr_count(rr) < 1 &&
	    knot_rrset_type(rr) != KNOT_RRTYPE_APL) {
		return KNOT_EMALF;
	}

	/* If we already have compressed name on the wire and compression hint,
	 * we can just insert RRSet and fake synthesis by using compression
	 * hint. */
	if (compr_hint == COMPR_HINT_NONE && knot_dname_is_wildcard(rr->owner)) {
		int ret = knot_rrset_deep_copy(rr, (knot_rrset_t **)&rr);
		if (ret != KNOT_EOK) {
			return KNOT_ENOMEM;
		}

		knot_rrset_set_owner((knot_rrset_t *)rr, qdata->name);
		flags |= KNOT_PF_FREE;
	}

	return knot_pkt_put(pkt, compr_hint, rr, flags);
}

/*! \brief Put RR into packet, but don't truncate if it doesn't fit. */
static int put_rr_optional(knot_pkt_t *pkt, const knot_rrset_t *rr, uint32_t flags)
{
	if (rr == NULL) {
		return KNOT_ENOENT;
	}

	int ret = knot_pkt_put(pkt, 0, rr, flags|KNOT_PF_NOTRUNC);
	if (ret == KNOT_ESPACE) {
		ret = KNOT_EOK;
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
		if (knot_zone_contents_any_disabled(qdata->zone->contents)) {
			knot_wire_set_tc(pkt->wire);
			return KNOT_EOK;
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
static int put_authority_ns(knot_pkt_t *pkt, const knot_zone_contents_t *zone)
{
	dbg_ns("%s(%p, %p)\n", __func__, pkt, zone);
	return put_rr_optional(pkt, knot_node_rrset(zone->apex, KNOT_RRTYPE_NS), 0);
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
	uint32_t flags = 0;
	uint32_t min = knot_rdata_soa_minimum(soa_rrset);
	if (min < knot_rrset_ttl(soa_rrset)) {
		ret = knot_rrset_deep_copy(soa_rrset, &soa_rrset);
		if (ret != KNOT_EOK) {
			return ret;
		}

		knot_rrset_set_ttl(soa_rrset, min);
		flags |= KNOT_PF_FREE;
	}

	return put_rr_optional(pkt, soa_rrset, flags);
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
	int ret = knot_pkt_put(pkt, 0, rrset, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return ret;
}

/*! \brief Put DS RRset or NSEC/NSEC3 proof if it doesn't exist. */
static int put_delegation_dnssec(knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Add DS record if present. */
	knot_rrset_t *rrset = knot_node_get_rrset(qdata->node, KNOT_RRTYPE_DS);
	if (rrset != NULL) {
		return knot_pkt_put(pkt, 0, rrset, 0);
	}

	/* DS doesn't exist => NODATA proof. */
	return ns_put_nsec_nsec3_nodata(qdata->node,
	                                qdata->encloser,
	                                qdata->previous,
	                                qdata->zone->contents,
	                                qdata->name, pkt);
}

static int follow_cname(knot_pkt_t *pkt, uint16_t rrtype, struct query_data *qdata)
{
	dbg_ns("%s(%p, %p)\n", __func__, pkt, qdata);

	const knot_node_t *cname_node = qdata->node;
	knot_rrset_t *cname_rr = knot_node_get_rrset(qdata->node, rrtype);
	int ret = KNOT_EOK;
	unsigned flags = 0;

	assert(cname_rr != NULL);

	/* Is node a wildcard? */
	if (knot_dname_is_wildcard(cname_node->owner)) {

		/* Check if is not in wildcard nodes (loop). */
		dbg_ns("%s: CNAME node %p is wildcard\n", __func__, cname_node);
		if (wildcard_has_visited(qdata, cname_node)) {
			dbg_ns("%s: node %p already visited => CNAME loop\n",
			       __func__, cname_node);
			return HIT;
		}

		/* Put to wildcard node list. */
		if (wildcard_visit(qdata, cname_node, qdata->name) != KNOT_EOK) {
			return ERROR;
		}

	} else {
		/* Normal CNAME name, check for duplicate. */
		flags |= KNOT_PF_CHECKDUP;
	}

	/* Now, try to put CNAME to answer. */
	uint16_t rr_count_before = pkt->rrset_count;
	ret = put_rr(pkt, cname_rr, 0, flags, qdata);
	if (ret != KNOT_EOK) {
		if (ret == KNOT_ESPACE) {
			return TRUNC;
		} else {
			return ERROR;
		}
	} else {
		/* Check if RR count increased. */
		if (pkt->rrset_count <= rr_count_before) {
			dbg_ns("%s: RR %p already inserted => CNAME loop\n",
			       __func__, cname_rr);
			return HIT;
		}
	}

	/* Synthesize CNAME if followed DNAME. */
	if (rrtype == KNOT_RRTYPE_DNAME) {
		if (dname_cname_can_synth(cname_rr, qdata->name)) {
			qdata->rcode = KNOT_RCODE_YXDOMAIN;
			return ERROR;
		}
		knot_rrset_t *synth_cname = dname_cname_synth(cname_rr, qdata->name);
		ret = put_rr(pkt, synth_cname, 0, KNOT_PF_FREE, qdata);
		if (ret == KNOT_ESPACE) {
			return TRUNC;
		} else if (ret != KNOT_EOK) {
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

		/* Put to wildcard node list. */
		if (wildcard_visit(qdata, qdata->encloser, qdata->name) != KNOT_EOK) {
			return ERROR;
		}

		return name_found(pkt, qdata);
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
	case KNOT_ZONE_NAME_FOUND:
		return name_found(pkt, qdata);
	case KNOT_ZONE_NAME_NOT_FOUND:
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
		/* Chain lead to NXDOMAIN, this is okay since
		 * the first CNAME/DNAME is a valid answer. */
		if (state == MISS) {
			state = HIT;
		}
	}

	return state;
}

static int solve_answer_dnssec(int state, knot_pkt_t *pkt, struct query_data *qdata)
{
	/* \todo write RRSIGs. */
	return state;
}

static int solve_authority_dnssec(int state, knot_pkt_t *pkt, struct query_data *qdata)
{
	/* \todo write RRSIGs. */

	int ret = KNOT_ERROR;
	const knot_zone_contents_t *zone_contents = qdata->zone->contents;

	switch (state) {
	case HIT:
		/* Put NSEC/NSEC3 Wildcard proof if answered from wildcard. */
		ret = wildcard_list_cover(pkt, qdata);
		break;
	case MISS:
		ret = ns_put_nsec_nsec3_nxdomain(zone_contents,
		                                 qdata->previous,
		                                 qdata->encloser,
		                                 qdata->name, pkt);
		break;
	case NODATA:
		ret = ns_put_nsec_nsec3_nodata(qdata->node,
		                               qdata->encloser,
		                               qdata->previous,
		                               qdata->zone->contents,
		                               qdata->name, pkt);
		break;
	case DELEG:
		ret = put_delegation_dnssec(pkt, qdata);
		break;
	case TRUNC:  /* Truncated ANSWER. */
		ret = KNOT_ESPACE;
		break;
	case ERROR:  /* Error resolving ANSWER. */
		break;
	default:
		dbg_ns("%s: invalid state after qname processing = %d\n",
		       __func__, state);
		assert(0);
		break;
	}

	return ret;
}

static int solve_authority(int state, knot_pkt_t *pkt, struct query_data *qdata)
{
	int ret = KNOT_ERROR;
	uint16_t qtype = knot_pkt_type(pkt);
	const knot_zone_contents_t *zone_contents = qdata->zone->contents;

	switch (state) {
	case HIT:    /* Positive response, add (optional) AUTHORITY NS. */
		dbg_ns("%s: answer is POSITIVE\n", __func__);
		/* DS/DNSKEY queries are not referrals => auth. NS is optional.
		 * But taking response size into consideration, DS/DNSKEY RRs
		 * are rather large and may trigger fragmentation or even TCP
		 * recovery. */
		if (qtype != KNOT_RRTYPE_DS && qtype != KNOT_RRTYPE_DNSKEY) {
			ret = put_authority_ns(pkt, zone_contents);

		} else {
			ret = KNOT_EOK;
		}
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
		dbg_ns("%s: invalid state after qname processing = %d\n",
		       __func__, state);
		assert(0);
		break;
	}

	return ret;
}

int internet_answer(knot_pkt_t *response, struct query_data *qdata)
{
	dbg_ns("%s(%p, %p)\n", __func__, response, qdata);
	if (response == NULL || qdata == NULL) {
		return NS_PROC_FAIL;
	}

	NS_NEED_VALID_ZONE(qdata, KNOT_RCODE_REFUSED);

	/* Check features - DNSSEC. */
	if (knot_pkt_have_dnssec(qdata->pkt) &&
	    knot_zone_contents_is_signed(qdata->zone->contents)) {
		qdata->flags |= HAVE_DNSSEC;
	}

	/* Write answer RRs for QNAME. */
	dbg_ns("%s: writing %p ANSWER\n", __func__, response);
	knot_pkt_begin(response, KNOT_ANSWER);

	/* Get answer to QNAME. */
	qdata->name = knot_pkt_qname(response);
	int state = solve_answer_section(BEGIN, response, qdata);

	/* Solve DNSSEC for ANSWER. */
	state = solve_answer_dnssec(state, response, qdata);

	/* Resolve AUTHORITY. */
	dbg_ns("%s: writing %p AUTHORITY\n", __func__, response);
	knot_pkt_begin(response, KNOT_AUTHORITY);
	int ret = solve_authority(state, response, qdata);
	if (ret != KNOT_EOK) {
		if (ret == KNOT_ESPACE) {
			return NS_PROC_FINISH;
		} else {
			return NS_PROC_FAIL;
		}
	}

	/* Resolve DNSSEC for AUTHORITY. */
	if (have_dnssec(qdata)) {
		ret = solve_authority_dnssec(state, response, qdata);
		if (ret == KNOT_ESPACE) {
			return NS_PROC_FINISH;
		} else {
			return NS_PROC_FAIL;
		}
	}

	/* Resolve ADDITIONAL. */
	dbg_ns("%s: writing %p ADDITIONAL\n", __func__, response);
	knot_pkt_begin(response, KNOT_ADDITIONAL);
	ret = ns_put_additional(response);
	/* Optional section. */
	if (ret != KNOT_EOK && ret != KNOT_ESPACE) {
		return NS_PROC_FAIL;

	}

	/* Write RCODE. */
	knot_wire_set_rcode(response->wire, qdata->rcode);

	/* Complete response. */
	return NS_PROC_FINISH;
}
