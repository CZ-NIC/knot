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

/*! \brief Query processing states. */
enum {
	BEGIN,   /* Begin name resolution. */
	NODATA,  /* Positive result with NO data. */
	HIT,     /* Positive result. */
	MISS,    /* Negative result. */
	DELEG,   /* Result is delegation. */
	FOLLOW,  /* Resolution not complete (CNAME/DNAME chain). */
	ERROR    /* Resolution failed. */
};

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
		if (ptrlist_contains(&qdata->wildcards, cname_node)) {
			dbg_ns("%s: node %p already visited => CNAME loop\n",
			       __func__, cname_node);
			return HIT;
		}

		/* Put to wildcard node list. */
		if (ptrlist_add(&qdata->wildcards, cname_node, qdata->mm) == NULL) {
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
		return ERROR;
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
		return ERROR;
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

	int added = 0; /*! \todo useless */
	int ret = ns_put_answer(qdata->node, qdata->zone->contents, *name, qtype, pkt, &added, 0 /*! \todo check from pkt */);

	if (ret != KNOT_EOK) {
		dbg_ns("%s: failed answer from node %p (%d)\n", __func__, qdata->node, ret);
		/*! \todo set rcode */
		return ERROR;
	} else {
		dbg_ns("%s: answered, %d added\n", __func__, added);
	}

	// this is the only case when the servers answers from
	// particular node, i.e. the only case when it may return SOA
	// or NS records in Answer section
	if (knot_wire_get_tc(pkt->wire) == 0
	    && knot_pkt_have_dnssec(pkt->query)
	    && qdata->node == knot_zone_contents_apex(qdata->zone->contents)
	    && (qtype == KNOT_RRTYPE_SOA || qtype == KNOT_RRTYPE_NS)) {
		ret = ns_add_dnskey(qdata->node, pkt);
		if (ret != KNOT_EOK) {
			return ERROR;
		}
	}

	/* Check for NODATA. */
	if (added == 0) {
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
		qdata->encloser = wildcard_node;
		qdata->previous = NULL;
		return name_found(pkt, name, qdata);
	}

	/* Name is under DNAME, use it for substitution. */
	knot_rrset_t *dname_rrset = knot_node_get_rrset(qdata->encloser, KNOT_RRTYPE_DNAME);
	if (dname_rrset != NULL
	    && knot_rrset_rdata_rr_count(dname_rrset) > 0) {
		dbg_ns("%s: solving DNAME for name %p\n", __func__, *name);
		int ret = ns_process_dname(dname_rrset, name, pkt);
		if (ret != KNOT_EOK) {
			return ERROR;
		}

		return FOLLOW;
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
	const knot_zone_contents_t *zone_contents = qdata->zone->contents;

	switch (state) {
	case HIT:    /* Positive response, add (optional) AUTHORITY NS. */
		ret = ns_put_authority_ns(zone_contents, pkt);
		dbg_ns("%s: putting authority NS = %d\n", __func__, ret);
		if (ret == KNOT_ESPACE) { /* Optional. */
			ret = KNOT_EOK;
		}
		break;
	case MISS:   /* MISS, set NXDOMAIN RCODE. */
		qdata->rcode = KNOT_RCODE_NXDOMAIN;
		dbg_ns("%s: answer is NXDOMAIN\n", __func__);
	case NODATA: /* NODATA or NXDOMAIN, append AUTHORITY SOA. */
		ret = ns_put_authority_soa(zone_contents, pkt);
		dbg_ns("%s: putting authority SOA = %d\n", __func__, ret);
		break;
	case DELEG:  /* Referral response. */ /*! \todo DS + NS */
		ret = ns_referral(qdata->node, zone_contents, *qname, pkt, knot_pkt_qtype(pkt));
		break;
	case ERROR:
		dbg_ns("%s: failed to resolve qname\n", __func__);
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
		return NS_PROC_FAIL;

	}

	// add all missing NSECs/NSEC3s for wildcard nodes
	/*! \todo Make function accept query_data with zone+wcnodes */

	/* Resolve ADDITIONAL. */
	dbg_ns("%s: writing %p ADDITIONAL\n", __func__, response);
	knot_pkt_begin(response, KNOT_ADDITIONAL);
	ret = ns_put_additional(qdata->zone, response);
	if (ret != KNOT_EOK) {
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
