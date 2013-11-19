#include <config.h>
#include <stdio.h>
#include <urcu.h>

#include "libknot/nameserver/ns_proc_query.h"
#include "common/descriptor.h"
#include "libknot/common.h"
#include "libknot/consts.h"
#include "libknot/rdata.h"
#include "libknot/util/debug.h"
#include "libknot/nameserver/chaos.h"

struct query_data {
	uint16_t rcode;
	uint16_t rcode_tsig;
	knot_pkt_t *pkt;
	const knot_node_t *node, *encloser, *previous;
	list_t wildcards;
	mm_ctx_t *mm;
};

/* Forward decls. */
int answer_internet(knot_pkt_t *pkt, ns_proc_context_t *ctx);
int answer_chaos(knot_pkt_t *pkt, ns_proc_context_t *ctx);
static int tsig_check(knot_pkt_t *pkt);
static int zone_state(const knot_zone_t *zone);
static const knot_zone_t *find_query_zone(knot_pkt_t *pkt, knot_nameserver_t *ns);
static int prepare_answer(knot_pkt_t *query, knot_pkt_t *resp, knot_nameserver_t *ns);
static int in_zone_answer(knot_pkt_t *resp, struct query_data *qdata);

/*! \brief Module implementation. */
const ns_proc_module_t _ns_proc_query = {
  &ns_proc_query_begin,
  &ns_proc_query_reset,
  &ns_proc_query_finish,
  &ns_proc_query_in,
  &ns_proc_query_out,
  &ns_proc_query_err
};

#define QUERY_DATA(ctx) ((struct query_data *)(ctx)->data)

int ns_proc_query_begin(ns_proc_context_t *ctx)
{
	/* Initialize context. */
	assert(ctx);
	ctx->type = NS_PROC_QUERY_ID;
	ctx->data = ctx->mm.alloc(ctx->mm.ctx, sizeof(struct query_data));

	struct query_data *data = QUERY_DATA(ctx);
	memset(data, 0, sizeof(struct query_data));
	data->mm = &ctx->mm;

	/* Initialize list. */
	init_list(&data->wildcards);

	/* Await packet. */
	return NS_PROC_MORE;
}

int ns_proc_query_reset(ns_proc_context_t *ctx)
{
	/* Clear */
	assert(ctx);
	struct query_data *data = QUERY_DATA(ctx);
	knot_pkt_free(&data->pkt);
	data->rcode = KNOT_RCODE_NOERROR;
	data->rcode_tsig = 0;
	data->node = data->encloser = data->previous = NULL;

	/* Free wildcard list. */
	ptrlist_free(&data->wildcards, data->mm);

	/* Await packet. */
	return NS_PROC_MORE;
}
int ns_proc_query_finish(ns_proc_context_t *ctx)
{
	ns_proc_query_reset(ctx);
	ctx->mm.free(ctx->data);
	ctx->data = NULL;

	return NS_PROC_FINISH;
}
int ns_proc_query_in(knot_pkt_t *pkt, ns_proc_context_t *ctx)
{
	assert(pkt && ctx);
	struct query_data *data = QUERY_DATA(ctx);

	/* Check query type. */
	uint16_t query_type = knot_pkt_type(pkt);
	if (query_type != KNOT_QUERY_NORMAL) {
		dbg_ns("%s: query_type(%hu) != NORMAL_QUERY\n", __func__, query_type);
		return NS_PROC_NOOP; /* Refuse to process. */
	}

	/* Store for processing. */
	data->pkt = pkt;

	/* Check parse state. */
	if (pkt->parsed < pkt->size) {
		data->rcode = KNOT_RCODE_FORMERR;
		return NS_PROC_FAIL;
	}

	/* Check TSIG. */
	int ret = tsig_check(pkt);
	if (ret != KNOT_EOK) {
		data->rcode = KNOT_RCODE_NOTAUTH;
		data->rcode_tsig = ret;
		return NS_PROC_FAIL;
	}

	/* Declare having response. */
	return NS_PROC_FULL;
}

int ns_proc_query_out(knot_pkt_t *pkt, ns_proc_context_t *ctx)
{
	assert(pkt && ctx);
	struct query_data *data = QUERY_DATA(ctx);

	rcu_read_lock();

	/* Prepare answer. */
	int next_state = NS_PROC_FINISH;
	int ret = prepare_answer(data->pkt, pkt, ctx->ns);
	if (ret != KNOT_EOK) {
		data->rcode = KNOT_RCODE_SERVFAIL;
		next_state = NS_PROC_FAIL;
		goto finish;
	} else {
		data->rcode = KNOT_RCODE_NOERROR;
	}

	/* Answer based on qclass. */
	switch (knot_pkt_qclass(pkt)) {
	case KNOT_CLASS_CH:
		next_state = answer_chaos(pkt, ctx);
		break;
	case KNOT_CLASS_ANY:
	case KNOT_CLASS_IN:
		next_state = answer_internet(pkt, ctx);
		break;
	default:
		data->rcode = KNOT_RCODE_REFUSED;
		next_state = NS_PROC_FAIL;
		break;
	}

finish:

	rcu_read_unlock();
	return next_state;
}

int ns_proc_query_err(knot_pkt_t *pkt, ns_proc_context_t *ctx)
{
	assert(pkt && ctx);
	struct query_data *data = QUERY_DATA(ctx);
	dbg_ns("%s: making error response, rcode = %d\n",
	       __func__, data->rcode);

	/*! \todo Prettier error response. */

	/* Clear packet. */
	knot_pkt_clear(pkt);

	/* Copy MsgId, opcode and RD bit. Set RCODE. */
	knot_pkt_t *query = data->pkt;
	knot_wire_set_id(pkt->wire, knot_wire_get_id(query->wire));
	knot_wire_set_opcode(pkt->wire, knot_wire_get_opcode(query->wire));
	knot_wire_set_qr(pkt->wire);
	knot_wire_set_rcode(pkt->wire, data->rcode);
	if (knot_wire_get_rd(query->wire)) {
		knot_wire_set_rd(pkt->wire);
	}

	/* Resolved. */
	return NS_PROC_FINISH;
}

/*!
 * \brief Create a response for a given query in the CHAOS class.
 */
int answer_internet(knot_pkt_t *pkt, ns_proc_context_t *ctx)
{
	struct query_data *data = QUERY_DATA(ctx);
	int next_state = NS_PROC_FAIL;

	/* Check zone validity. */
	switch(zone_state(pkt->zone)) {
	case KNOT_EOK:     next_state = in_zone_answer(pkt, data); break;
	case KNOT_ENOENT:  data->rcode = KNOT_RCODE_REFUSED; break;
	default:           data->rcode = KNOT_RCODE_SERVFAIL; break;
	}

	return next_state;
}

/*!
 * \brief Create a response for a given query in the CHAOS class.
 */
int answer_chaos(knot_pkt_t *pkt, ns_proc_context_t *ctx)
{
	dbg_ns("%s(%p, %p)\n", __func__, pkt, ctx);
	struct query_data *data = QUERY_DATA(ctx);

	data->rcode = knot_chaos_answer(pkt, ctx->ns);
	if (data->rcode != KNOT_RCODE_NOERROR) {
		return NS_PROC_FAIL;
	}

	return NS_PROC_FINISH;
}

static int tsig_check(knot_pkt_t *pkt)
{
	/*! \todo TSIG for normal queries when we standardize API. */
	if (pkt->tsig_rr != NULL) {
		return KNOT_TSIG_EBADKEY;
	}

	return KNOT_EOK;
}

static int zone_state(const knot_zone_t *zone)
{
	if (zone == NULL) {
		dbg_ns("%s: zone not found\n", __func__);
		return KNOT_ENOENT;
	} else if (zone->contents == NULL) {
		dbg_ns("%s: zone expired or stub\n", __func__);
		return KNOT_ENOZONE;
	}
	return KNOT_EOK;
}

static const knot_zone_t *find_query_zone(knot_pkt_t *pkt, knot_nameserver_t *ns)
{
	uint16_t qtype = knot_pkt_qtype(pkt);
	uint16_t qclass = knot_pkt_qclass(pkt);
	const knot_dname_t *qname = knot_pkt_qname(pkt);

	// search for zone only for IN and ANY classes
	if (qclass != KNOT_CLASS_IN && qclass != KNOT_CLASS_ANY) {
		return NULL;
	}

	// find zone in which to search for the name
	knot_zonedb_t *zonedb = rcu_dereference(ns->zone_db);
	return ns_get_zone_for_qname(zonedb, qname, qtype);
}

static int prepare_answer(knot_pkt_t *query, knot_pkt_t *resp, knot_nameserver_t *ns)
{
	dbg_ns("%s(%p, %p, %p)\n", __func__, query, resp, ns);

	int ret = knot_pkt_init_response(resp, query);
	if (ret != KNOT_EOK) {
		dbg_ns("%s: can't init response pkt (%d)\n", __func__, ret);
		return ret;
	}

	// find zone for qname
	resp->zone = find_query_zone(query, ns);
	dbg_ns("%s: found zone %p for pkt %p\n", __func__, resp->zone, query);

	/* Check if EDNS is supported. */
	if (!knot_pkt_have_edns(query)) {
		return KNOT_EOK;
	}

	// set the OPT RR to the response
	ret = knot_pkt_add_opt(resp, ns->opt_rr, knot_pkt_have_nsid(query));
	if (ret == KNOT_EOK) {
		// copy the DO bit from the query
		if (knot_pkt_have_dnssec(query)) {
			dbg_ns("%s: setting DO=1 in OPT RR\n", __func__);
			knot_edns_set_do(&(resp)->opt_rr);
		}
	} else {
		dbg_ns("%s: can't add OPT RR (%d)\n", __func__, ret);
	}

	return ret;
}

enum {
	BEGIN,
	NODATA,
	HIT,
	MISS,
	DELEG,
	FOLLOW,
	ERROR
};

int in_zone_name_cname(knot_pkt_t *pkt, const knot_dname_t **name, struct query_data *qdata)
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
			qdata->rcode = KNOT_RCODE_SERVFAIL;
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
	ret = knot_pkt_put(pkt, 0, rr_to_add, flags);
	if (ret != KNOT_EOK) {
		/* Free if synthetized. */
		if (rr_to_add != cname_rr) {
			knot_rrset_deep_free(&rr_to_add, 1);
		}
		/* Duplicate found, end resolving chain. */
		if (ret == KNOT_ENORRSET) {
			dbg_ns("%s: RR %p already inserted => CNAME loop\n",
			       __func__, rr_to_add);
			return HIT;
		} else {
			qdata->rcode = KNOT_RCODE_SERVFAIL;
			return ERROR;
		}
	}

	/* Add RR signatures (from original RR). */
	ret = ns_add_rrsigs(cname_rr, pkt, *name, 0);
	if (ret != KNOT_EOK) {
		dbg_ns("%s: couldn't add rrsigs for CNAME RRSet %p\n",
		       __func__, cname_rr);
		qdata->rcode = KNOT_RCODE_SERVFAIL;
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

static int in_zone_name_found(knot_pkt_t *pkt, const knot_dname_t **name,
                              struct query_data *qdata)
{
	uint16_t qtype = knot_pkt_qtype(pkt);
	dbg_ns("%s(%p, %p, %p)\n", __func__, pkt, name, qdata);

	if (knot_node_rrset(qdata->node, KNOT_RRTYPE_CNAME) != NULL
	    && qtype != KNOT_RRTYPE_CNAME && qtype != KNOT_RRTYPE_RRSIG) {
		dbg_ns("%s: solving CNAME\n", __func__);
		return in_zone_name_cname(pkt, name, qdata);
	}

	// now we have the node for answering
	if (qtype != KNOT_RRTYPE_DS && // DS query is answered normally
	    (knot_node_is_deleg_point(qdata->node) || knot_node_is_non_auth(qdata->node))) {
		dbg_ns("%s: solving REFERRAL\n", __func__);
		return DELEG;
	}

	int added = 0; /*! \todo useless */
	int ret = ns_put_answer(qdata->node, pkt->zone->contents, *name, qtype, pkt, &added, 0 /*! \todo check from pkt */);

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
	    && qdata->node == knot_zone_contents_apex(pkt->zone->contents)
	    && (qtype == KNOT_RRTYPE_SOA || qtype == KNOT_RRTYPE_NS)) {
		ret = ns_add_dnskey(qdata->node, pkt);
		if (ret != KNOT_EOK) {
			qdata->rcode = KNOT_RCODE_SERVFAIL;
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

static int in_zone_name_not_found(knot_pkt_t *pkt, const knot_dname_t **name,
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
		return in_zone_name_found(pkt, name, qdata);
	}

	/* Name is under DNAME, use it for substitution. */
	knot_rrset_t *dname_rrset = knot_node_get_rrset(qdata->encloser, KNOT_RRTYPE_DNAME);
	if (dname_rrset != NULL
	    && knot_rrset_rdata_rr_count(dname_rrset) > 0) {
		dbg_ns("%s: solving DNAME for name %p\n", __func__, *name);
		int ret = ns_process_dname(dname_rrset, name, pkt);
		if (ret != KNOT_EOK) {
			qdata->rcode = KNOT_RCODE_SERVFAIL;
			return ERROR;
		}

		return FOLLOW;
	}

	dbg_ns("%s: name not found in zone %p\n", __func__, *name);
	return MISS;
}

static int in_zone_solve_name(int state, const knot_dname_t **name,
                                knot_pkt_t *pkt, struct query_data *qdata)
{
	dbg_ns("%s(%d, %p, %p, %p)\n", __func__, state, name, pkt, qdata);
	int ret = knot_zone_contents_find_dname(pkt->zone->contents, *name,
	                                        &qdata->node, &qdata->encloser,
	                                        &qdata->previous);

	switch(ret) {
	case KNOT_ZONE_NAME_FOUND:
		return in_zone_name_found(pkt, name, qdata);
	case KNOT_ZONE_NAME_NOT_FOUND:
		return in_zone_name_not_found(pkt, name, qdata);
	case KNOT_EOUTOFZONE:
		assert(state == FOLLOW); /* CNAME/DNAME chain only. */
		return HIT;
	default:
		return ERROR;
	}
}

static int in_zone_solve_answer(const knot_dname_t **qname,
                                    knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Get answer to QNAME. */
	int state = in_zone_solve_name(BEGIN, qname, pkt, qdata);

	/* Is authoritative answer unless referral.
	 * Must check before we chase the CNAME chain. */
	if (state != DELEG) {
		knot_wire_set_aa(pkt->wire);
	}

	/* Additional resolving for CNAME/DNAME chain. */
	while (state == FOLLOW) {
		state = in_zone_solve_name(state, qname, pkt, qdata);
		/* Chain lead to NXDOMAIN, this is okay since
		 * the first CNAME/DNAME is a valid answer. */
		if (state == MISS) {
			state = HIT;
		}
	}

	return state;
}

static int in_zone_solve_authority(int state, const knot_dname_t **qname,
                                   knot_pkt_t *pkt, struct query_data *qdata)
{
	int ret = KNOT_ERROR;

	switch (state) {
	case HIT:    /* Positive response, add (optional) AUTHORITY NS. */
		ret = ns_put_authority_ns(pkt->zone->contents, pkt);
		dbg_ns("%s: putting authority NS = %d\n", __func__, ret);
		break;
	case MISS:   /* MISS, set NXDOMAIN RCODE. */
		qdata->rcode = KNOT_RCODE_NXDOMAIN;
		dbg_ns("%s: answer is NXDOMAIN\n", __func__);
	case NODATA: /* NODATA or NXDOMAIN, append AUTHORITY SOA. */
		ret = ns_put_authority_soa(pkt->zone->contents, pkt);
		dbg_ns("%s: putting authority SOA = %d\n", __func__, ret);
		break;
	case DELEG:  /* Referral response. */ /*! \todo DS + NS */
		ret = ns_referral(qdata->node, pkt->zone->contents, *qname, pkt, knot_pkt_qtype(pkt));
		break;
	case ERROR:
		dbg_ns("%s: failed to resolve qname\n", __func__);
		break;
	default:
		dbg_ns("%s: invalid state after qname processing = %d\n",
		       __func__, state);
		assert(0);
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		break;
	}

	return ret;
}

static int in_zone_answer(knot_pkt_t *resp, struct query_data *qdata)
{
	dbg_ns("%s(%p, %p)\n", __func__, resp, qdata);

	/* Write answer RRs for QNAME. */
	dbg_ns("%s: writing %p ANSWER\n", __func__, resp);
	knot_pkt_begin(resp, KNOT_ANSWER);

	const knot_dname_t *qname = knot_pkt_qname(resp);

	/* Get answer to QNAME. */
	int state = in_zone_solve_answer(&qname, resp, qdata);

	/* Resolve AUTHORITY. */
	dbg_ns("%s: writing %p AUTHORITY\n", __func__, resp);
	knot_pkt_begin(resp, KNOT_AUTHORITY);
	int ret = in_zone_solve_authority(state, &qname, resp, qdata);
	if (ret != KNOT_EOK) {
		return NS_PROC_FAIL;

	}

	// add all missing NSECs/NSEC3s for wildcard nodes
	/*! \todo Make function accept query_data with zone+wcnodes */

	/* Resolve ADDITIONAL. */
	dbg_ns("%s: writing %p ADDITIONAL\n", __func__, resp);
	knot_pkt_begin(resp, KNOT_ADDITIONAL);
	ret = ns_put_additional(resp);
	if (ret != KNOT_EOK) {
		return NS_PROC_FAIL;

	}

	/* Write RCODE. */
	knot_wire_set_rcode(resp->wire, qdata->rcode);

	/* Complete response. */
	return NS_PROC_FINISH;
}
