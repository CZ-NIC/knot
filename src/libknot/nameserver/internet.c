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

/*! \brief DNSSEC both requested & available. */
static bool have_dnssec(struct query_data *qdata)
{
	return qdata->flags & HAVE_DNSSEC;
}

/*! \brief Put RRSet and its RRSIG (if applicable) to packet. */
static int put_answer_rr(knot_pkt_t *pkt, const knot_rrset_t *rr,
			 const knot_dname_t *qname, struct query_data *qdata)
{
	/* RFC3123 s.6 - empty APL is valid, ignore other empty RRs. */
	if (knot_rrset_rdata_rr_count(rr) < 1 &&
	    knot_rrset_type(rr) != KNOT_RRTYPE_APL) {
		return KNOT_EMALF;
	}

	uint16_t flags = 0;
	uint16_t compr_hint = COMPR_HINT_NONE;

	/* Wildcard expansion or exact match, either way RRSet owner is
	 * is QNAME. We can fake name synthesis by setting compression hint to
	 * QNAME position. Just need to check if we're answering QNAME and not
	 * a CNAME target.
	 */
	if (pkt->rrset_count == 0) { /* Guaranteed first answer. */
		compr_hint = COMPR_HINT_QNAME;
	} else {
		if (knot_dname_is_wildcard(rr->owner)) {
			rr = ns_synth_from_wildcard(rr, qname);
			flags |= KNOT_PF_FREE;
		}
	}

	/*! \todo I don't like this much, RRSIGS could be added to whole section
	 *        after processing I think. */
	int ret = knot_pkt_put(pkt, compr_hint, rr, flags);
	if (ret == KNOT_EOK && rr->rrsigs && have_dnssec(qdata)) {
		ret = put_answer_rr(pkt, rr->rrsigs, qname, qdata);
	}

	return ret;
}

/*! \brief This is a wildcard-covered or any other terminal node for QNAME.
 *         e.g. positive answer.
 */
static int put_answer_node(knot_pkt_t *pkt, uint16_t type,
			   const knot_dname_t *qname, struct query_data *qdata)
{
	const knot_rrset_t *rrset = NULL;
	knot_rrset_t **rrsets = knot_node_get_rrsets_no_copy(qdata->node);

	int ret = KNOT_EOK;
	switch (type) {
	case KNOT_RRTYPE_ANY: /* Append all RRSets. */
		/* If ANY not allowed, set TC bit. */
		if (knot_zone_contents_any_disabled(qdata->zone->contents)) {
			knot_wire_set_tc(pkt->wire);
			return KNOT_EOK;
		}
		for (unsigned i = 0; i < knot_node_rrset_count(qdata->node); ++i) {
			ret = put_answer_rr(pkt, rrsets[i], qname, qdata);
			if (ret != KNOT_EOK) {
				break;
			}
		}
		break;
	case KNOT_RRTYPE_RRSIG: /* Append all RRSIGs. */
		for (unsigned i = 0; i < knot_node_rrset_count(qdata->node); ++i) {
			if (rrsets[i]->rrsigs) {
				ret = put_answer_rr(pkt, rrsets[i]->rrsigs, qname, qdata);
				if (ret != KNOT_EOK) {
					break;
				}
			}
		}
		break;
	default: /* Single RRSet of given type. */
		rrset = knot_node_get_rrset(qdata->node, type);
		if (rrset) {
			ret = put_answer_rr(pkt, rrset, qname, qdata);
		}
		break;
	}

	return ret;
}

static int follow_cname(knot_pkt_t *pkt, const knot_dname_t **name, struct query_data *qdata)
{
	dbg_ns("%s(%p, %p, %p)\n", __func__, name, pkt, qdata);

	const knot_node_t *cname_node = qdata->node;
	knot_rrset_t *cname_rr = knot_node_get_rrset(qdata->node, KNOT_RRTYPE_CNAME);
	knot_rrset_t *rr_to_add = cname_rr;
	unsigned flags = 0;
	int ret = KNOT_EOK;

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
		if (wildcard_visit(qdata, cname_node, *name) != KNOT_EOK) {
			return ERROR;
		}

		/* Synthetic RRSet. */
		rr_to_add = ns_synth_from_wildcard(cname_rr, *name);

		/* Free RRSet with packet. */
		flags |= KNOT_PF_FREE;

	} else {
		/* Normal CNAME name, check for duplicate. */
		flags |= KNOT_PF_CHECKDUP;
	}

	/* Now, try to put CNAME to answer. */
	uint16_t rr_count_before = pkt->rrset_count;
	ret = knot_pkt_put(pkt, 0, rr_to_add, flags);
	if (ret != KNOT_EOK) {
		/* Free if synthetized. */
		if (rr_to_add != cname_rr) {
			knot_rrset_deep_free(&rr_to_add, 1);
		}
		if (ret == KNOT_ESPACE) {
			return TRUNC;
		} else {
			return ERROR;
		}
	} else {
		/* Check if RR count increased. */
		if (pkt->rrset_count <= rr_count_before) {
			dbg_ns("%s: RR %p already inserted => CNAME loop\n",
			       __func__, rr_to_add);
			return HIT;
		}
	}

	/* Add RR signatures (from original RR). */
	ret = ns_add_rrsigs(cname_rr, pkt, *name, 0);
	if (ret != KNOT_EOK) {
		dbg_ns("%s: couldn't add rrsigs for CNAME RRSet %p\n",
		       __func__, cname_rr);
		if (ret == KNOT_ESPACE) {
			return TRUNC;
		} else {
			return ERROR;
		}
	}

	/* Now follow the next CNAME TARGET. */
	*name = knot_rdata_cname_name(cname_rr);

#ifdef KNOT_NS_DEBUG
	char *cname_str = knot_dname_to_str(cname_node->owner);
	char *target_str = knot_dname_to_str(*name);
	dbg_ns("%s: FOLLOW '%s' -> '%s'\n", __func__, cname_str, target_str);
	free(cname_str);
	free(target_str);
#endif /* KNOT_NS_DEBUG */

	return FOLLOW;
}

static int name_found(knot_pkt_t *pkt, const knot_dname_t **name,
                      struct query_data *qdata)
{
	uint16_t qtype = knot_pkt_qtype(pkt);
	dbg_ns("%s(%p, %p, %p)\n", __func__, pkt, name, qdata);

	if (knot_node_rrset(qdata->node, KNOT_RRTYPE_CNAME) != NULL
	    && qtype != KNOT_RRTYPE_CNAME
	    && qtype != KNOT_RRTYPE_RRSIG
	    && qtype != KNOT_RRTYPE_ANY) {
		dbg_ns("%s: solving CNAME\n", __func__);
		return follow_cname(pkt, name, qdata);
	}

	// now we have the node for answering
	if (qtype != KNOT_RRTYPE_DS && // DS query is answered normally
	    (knot_node_is_deleg_point(qdata->node) || knot_node_is_non_auth(qdata->node))) {
		dbg_ns("%s: solving REFERRAL\n", __func__);
		return DELEG;
	}

	uint16_t old_rrcount = pkt->rrset_count;
	int ret = put_answer_node(pkt, qtype, *name, qdata);
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

static int name_not_found(knot_pkt_t *pkt, const knot_dname_t **name,
                          struct query_data *qdata)
{
	dbg_ns("%s(%p, %p, %p)\n", __func__, pkt, name, qdata);

	/* Name is covered by wildcard. */
	const knot_node_t *wildcard_node = knot_node_wildcard_child(qdata->encloser);
	if (wildcard_node) {
		dbg_ns("%s: name %p covered by wildcard\n", __func__, *name);
		qdata->node = wildcard_node;
		/* keep encloser */
		qdata->previous = NULL;

		/* Put to wildcard node list. */
		if (wildcard_visit(qdata, qdata->encloser, *name) != KNOT_EOK) {
			return ERROR;
		}

		return name_found(pkt, name, qdata);
	}

	/* Name is under DNAME, use it for substitution. */
	knot_rrset_t *dname_rrset = knot_node_get_rrset(qdata->encloser, KNOT_RRTYPE_DNAME);
	if (dname_rrset != NULL
	    && knot_rrset_rdata_rr_count(dname_rrset) > 0) {
		dbg_ns("%s: solving DNAME for name %p\n", __func__, *name);
		int ret = ns_process_dname(dname_rrset, name, pkt);
		if (ret != KNOT_EOK) {
			if (ret == KNOT_ESPACE) {
				return TRUNC;
			} else {
				return ERROR;
			}
		}

		return FOLLOW;
	}

	/* Name is below delegation. */
	if (knot_node_is_deleg_point(qdata->encloser)) {
		dbg_ns("%s: name below delegation point %p\n", __func__, *name);
		qdata->node = qdata->encloser;
		return DELEG;
	}

	dbg_ns("%s: name not found in zone %p\n", __func__, *name);
	return MISS;
}

static int solve_name(int state, const knot_dname_t **name,
                      knot_pkt_t *pkt, struct query_data *qdata)
{
	dbg_ns("%s(%d, %p, %p, %p)\n", __func__, state, name, pkt, qdata);
	int ret = knot_zone_contents_find_dname(qdata->zone->contents, *name,
	                                        &qdata->node, &qdata->encloser,
	                                        &qdata->previous);

	switch(ret) {
	case KNOT_ZONE_NAME_FOUND:
		return name_found(pkt, name, qdata);
	case KNOT_ZONE_NAME_NOT_FOUND:
		return name_not_found(pkt, name, qdata);
	case KNOT_EOUTOFZONE:
		assert(state == FOLLOW); /* CNAME/DNAME chain only. */
		return HIT;
	default:
		return ERROR;
	}
}

static int solve_answer_section(const knot_dname_t **qname,
                                knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Get answer to QNAME. */
	int state = solve_name(BEGIN, qname, pkt, qdata);

	/* Is authoritative answer unless referral.
	 * Must check before we chase the CNAME chain. */
	if (state != DELEG) {
		knot_wire_set_aa(pkt->wire);
	}

	/* Additional resolving for CNAME/DNAME chain. */
	while (state == FOLLOW) {
		state = solve_name(state, qname, pkt, qdata);
		/* Chain lead to NXDOMAIN, this is okay since
		 * the first CNAME/DNAME is a valid answer. */
		if (state == MISS) {
			state = HIT;
		}
	}

	return state;
}

static int solve_authority(int state, const knot_dname_t **qname,
                           knot_pkt_t *pkt, struct query_data *qdata)
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
			ret = ns_put_authority_ns(zone_contents, pkt);
			if (ret == KNOT_ESPACE) { /* Optional. */
				ret = KNOT_EOK;
			}
		} else {
			ret = KNOT_EOK;
		}
		/* Put NSEC/NSEC3 Wildcard proof if answered from wildcard. */
		if (ret == KNOT_EOK && have_dnssec(qdata)) {
			ret = wildcard_list_cover(pkt, qdata);
		}
		break;
	case MISS:   /* MISS, set NXDOMAIN RCODE. */
		dbg_ns("%s: answer is NXDOMAIN\n", __func__);
		qdata->rcode = KNOT_RCODE_NXDOMAIN;
		ret = ns_put_authority_soa(zone_contents, pkt);
		if (ret == KNOT_EOK && have_dnssec(qdata)) {
			ret = ns_put_nsec_nsec3_nxdomain(zone_contents,
							 qdata->previous,
							 qdata->encloser,
							 *qname, pkt);
		}
		break;
	case NODATA: /* NODATA append AUTHORITY SOA + NSEC/NSEC3. */
		dbg_ns("%s: answer is NODATA\n", __func__);
		ret = ns_put_authority_soa(zone_contents, pkt);
		if (ret == KNOT_EOK && have_dnssec(qdata)) {
			if (knot_dname_is_wildcard(qdata->node->owner)) {
				ret = ns_put_nsec_nsec3_wildcard_nodata(qdata->node,
									qdata->encloser,
									qdata->previous,
									qdata->zone->contents,
									*qname, pkt);
			} else {
				ret = ns_put_nsec_nsec3_nodata(zone_contents,
							       qdata->node,
							       *qname, pkt);
			}
		}
		break;
	case DELEG:  /* Referral response. */
		ret = ns_referral(qdata->node, zone_contents, *qname, pkt, qtype);
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

	const knot_dname_t *qname = knot_pkt_qname(response);

	/* Get answer to QNAME. */
	int state = solve_answer_section(&qname, response, qdata);

	/* Resolve AUTHORITY. */
	dbg_ns("%s: writing %p AUTHORITY\n", __func__, response);
	knot_pkt_begin(response, KNOT_AUTHORITY);
	int ret = solve_authority(state, &qname, response, qdata);
	if (ret != KNOT_EOK) {
		/* Truncated. */
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

/* Messages. */
#define NOTIFY_MSG "NOTIFY of '%s' from %s: "
#define NOTIFY_XMSG "received serial %u."

static int notify_reschedule(knot_nameserver_t *ns,
                             const knot_zone_t *zone,
                             sockaddr_t *from)
{
	dbg_ns("%s(%p, %p, %p)\n", __func__, ns, zone, from);
	if (ns == NULL || zone == NULL || zone->data == NULL) {
		return KNOT_EINVAL;
	}

	/* Check ACL for notify-in. */
	zonedata_t *zone_data = (zonedata_t *)knot_zone_data(zone);
	if (from) {
		if (acl_find(zone_data->notify_in, from) == NULL) {
			return KNOT_EDENIED;
		}
	} else {
		dbg_ns("%s: no zone data/address, can't do ACL check\n", __func__);
	}

	/* Cancel REFRESH/RETRY timer. */
	server_t *server = ns->data;
	event_t *refresh_ev = zone_data->xfr_in.timer;
	if (refresh_ev && server) {
		dbg_ns("%s: expiring REFRESH timer\n", __func__);
		evsched_cancel(server->sched, refresh_ev);
		evsched_schedule(server->sched, refresh_ev, 0);
	} else {
		dbg_ns("%s: no REFRESH timer to expire\n", __func__);
	}

	return KNOT_EOK;
}

int internet_notify(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	if (pkt == NULL || ns == NULL || qdata == NULL) {
		return NS_PROC_FAIL;
	}

	/* RFC1996 require SOA question. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_SOA, KNOT_RCODE_FORMERR);
	/*! \note NOTIFY/RFC1996 isn't clear on error RCODEs.
	 *        Most servers use NOTAUTH from RFC2136. */
	NS_NEED_VALID_ZONE(qdata, KNOT_RCODE_NOTAUTH);

	/* SOA RR in answer may be included, recover serial. */
	unsigned serial = 0;
	const knot_pktsection_t *answer = knot_pkt_section(qdata->pkt, KNOT_ANSWER);
	if (answer->count > 0) {
		const knot_rrset_t *soa = answer->rr[0];
		if (knot_rrset_type(soa) == KNOT_RRTYPE_SOA) {
			serial = knot_rdata_soa_serial(soa);
			dbg_ns("%s: received serial %u\n", __func__, serial);
		} else { /* Ignore */
			dbg_ns("%s: NOTIFY answer != SOA_RR\n", __func__);
		}
	}

	int next_state = NS_PROC_FAIL;
	int ret = notify_reschedule(ns, qdata->zone, NULL /*! \todo API */);

	/* Format resulting log message. */
	char *qname_str = knot_dname_to_str(knot_pkt_qname(pkt));
	char *addr_str = strdup("(noaddr)"); /* xfr_remote_str(from, NULL); */ /*! \todo API */
	if (ret != KNOT_EOK) {
		next_state = NS_PROC_NOOP; /* RFC1996: Ignore. */
		log_server_warning(NOTIFY_MSG "%s\n", qname_str, addr_str, knot_strerror(ret));
	} else {
		next_state = NS_PROC_FINISH;
		log_server_info(NOTIFY_MSG NOTIFY_XMSG "\n", qname_str, addr_str, serial);
	}
	free(qname_str);
	free(addr_str);

	return next_state;
}
