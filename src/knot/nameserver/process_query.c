#include <stdio.h>
#include <urcu.h>

#include "knot/nameserver/process_query.h"
#include "knot/nameserver/chaos.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/axfr.h"
#include "knot/nameserver/ixfr.h"
#include "knot/nameserver/update.h"
#include "knot/nameserver/nsec_proofs.h"
#include "knot/nameserver/notify.h"
#include "knot/server/server.h"
#include "knot/server/rrl.h"
#include "knot/updates/acl.h"
#include "knot/conf/conf.h"
#include "libknot/tsig-op.h"
#include "common/descriptor.h"
#include "common/debug.h"

/*! \brief Accessor to query-specific data. */
#define QUERY_DATA(ctx) ((struct query_data *)(ctx)->data)

/*! \brief Reinitialize query data structure. */
static void query_data_init(knot_process_t *ctx, void *module_param)
{
	/* Initialize persistent data. */
	struct query_data *data = QUERY_DATA(ctx);
	memset(data, 0, sizeof(struct query_data));
	data->mm = &ctx->mm;
	data->param = (struct process_query_param*)module_param;

	/* Initialize lists. */
	init_list(&data->wildcards);
	init_list(&data->rrsigs);
}

static int process_query_begin(knot_process_t *ctx, void *module_param)
{
	/* Initialize context. */
	assert(ctx);
	ctx->type = NS_PROC_QUERY_ID;
	ctx->data = mm_alloc(&ctx->mm, sizeof(struct query_data));

	/* Initialize persistent data. */
	query_data_init(ctx, module_param);

	/* Await packet. */
	return NS_PROC_MORE;
}

static int process_query_reset(knot_process_t *ctx)
{
	assert(ctx);
	struct query_data *qdata = QUERY_DATA(ctx);

	/* Remember persistent parameters. */
	struct process_query_param *module_param = qdata->param;

	/* Free allocated data. */
	knot_pkt_free(&qdata->query);
	ptrlist_free(&qdata->wildcards, qdata->mm);
	nsec_clear_rrsigs(qdata);
	if (qdata->ext_cleanup != NULL) {
		qdata->ext_cleanup(qdata);
	}

	/* Initialize persistent data. */
	query_data_init(ctx, module_param);

	/* Await packet. */
	return NS_PROC_MORE;
}

static int process_query_finish(knot_process_t *ctx)
{
	process_query_reset(ctx);
	ctx->mm.free(ctx->data);
	ctx->data = NULL;

	return NS_PROC_NOOP;
}

static int process_query_in(knot_pkt_t *pkt, knot_process_t *ctx)
{
	assert(pkt && ctx);
	struct query_data *qdata = QUERY_DATA(ctx);

	/* Check if at least header is parsed. */
	if (pkt->parsed < KNOT_WIRE_HEADER_SIZE) {
		knot_pkt_free(&pkt);
		return NS_PROC_NOOP; /* Ignore. */
	}

	/* Accept only queries. */
	if (knot_wire_get_qr(pkt->wire)) {
		knot_pkt_free(&pkt);
		return NS_PROC_NOOP; /* Ignore. */
	}

	/* Store for processing. */
	qdata->query = pkt;
	qdata->packet_type = knot_pkt_type(pkt);

	/* Declare having response. */
	return NS_PROC_FULL;
}

/*!
 * \brief Create a response for a given query in the INTERNET class.
 */
static int query_internet(knot_pkt_t *pkt, knot_process_t *ctx)
{
	struct query_data *data = QUERY_DATA(ctx);
	int next_state = NS_PROC_FAIL;
	dbg_ns("%s(%p, %p, pkt_type=%u)\n", __func__, pkt, ctx, data->packet_type);

	switch(data->packet_type) {
	case KNOT_QUERY_NORMAL:
		next_state = internet_query(pkt, data);
		break;
	case KNOT_QUERY_NOTIFY:
		next_state = notify_process_query(pkt, data);
		break;
	case KNOT_QUERY_AXFR:
		next_state = axfr_query_process(pkt, data);
		break;
	case KNOT_QUERY_IXFR:
		next_state = ixfr_query(pkt, data);
		break;
	case KNOT_QUERY_UPDATE:
		next_state = update_query_process(pkt, data);
		break;
	default:
		/* Nothing else is supported. */
		data->rcode = KNOT_RCODE_NOTIMPL;
		next_state = NS_PROC_FAIL;
		break;
	}

	return next_state;
}

/*!
 * \brief Create a response for a given query in the CHAOS class.
 */
static int query_chaos(knot_pkt_t *pkt, knot_process_t *ctx)
{
	dbg_ns("%s(%p, %p)\n", __func__, pkt, ctx);
	struct query_data *data = QUERY_DATA(ctx);

	/* Nothing except normal queries is supported. */
	if (data->packet_type != KNOT_QUERY_NORMAL) {
		data->rcode = KNOT_RCODE_NOTIMPL;
		return NS_PROC_FAIL;
	}

	data->rcode = knot_chaos_answer(pkt);
	if (data->rcode != KNOT_RCODE_NOERROR) {
		dbg_ns("%s: failed with RCODE=%d\n", __func__, data->rcode);
		return NS_PROC_FAIL;
	}

	return NS_PROC_DONE;
}

static int process_query_sign_response(knot_pkt_t *pkt, struct query_data *qdata)
{
	if (pkt->size == 0) {
		// Nothing to sign.
		return KNOT_EOK;
	}

	int ret = KNOT_EOK;
	knot_pkt_t *query = qdata->query;
	knot_sign_context_t *ctx = &qdata->sign;

	/* KEY provided and verified TSIG or BADTIME allows signing. */
	if (ctx->tsig_key != NULL && knot_tsig_can_sign(qdata->rcode_tsig)) {

		/* Sign query response. */
		dbg_ns("%s: signing response using key %p\n", __func__, ctx->tsig_key);
		size_t new_digest_len = knot_tsig_digest_length(ctx->tsig_key->algorithm);
		if (ctx->pkt_count == 0) {
			ret = knot_tsig_sign(pkt->wire, &pkt->size, pkt->max_size,
			                     ctx->tsig_digest, ctx->tsig_digestlen,
			                     ctx->tsig_digest, &new_digest_len,
			                     ctx->tsig_key, qdata->rcode_tsig,
			                     ctx->tsig_time_signed);
		} else {
			ret = knot_tsig_sign_next(pkt->wire, &pkt->size, pkt->max_size,
			                          ctx->tsig_digest, ctx->tsig_digestlen,
			                          ctx->tsig_digest, &new_digest_len,
			                          ctx->tsig_key,
			                          pkt->wire, pkt->size);
		}
		if (ret != KNOT_EOK) {
			goto fail; /* Failed to sign. */
		} else {
			++ctx->pkt_count;
		}
	} else {
		/* Copy TSIG from query and set RCODE. */
		if (query->tsig_rr && qdata->rcode_tsig != KNOT_RCODE_NOERROR) {
			dbg_ns("%s: appending original TSIG\n", __func__);
			ret = knot_tsig_add(pkt->wire, &pkt->size, pkt->max_size,
			                    qdata->rcode_tsig, query->tsig_rr);
			if (ret != KNOT_EOK) {
				goto fail; /* Whatever it is, it's server fail. */
			}
		}
	}

	return ret;

	/* Server failure in signing. */
fail:
	dbg_ns("%s: signing failed (%s)\n", __func__, knot_strerror(ret));
	qdata->rcode = KNOT_RCODE_SERVFAIL;
	qdata->rcode_tsig = KNOT_RCODE_NOERROR; /* Don't sign again. */
	return ret;
}

/*! \brief Find zone for given question. */
static const zone_t *answer_zone_find(const knot_pkt_t *query, knot_zonedb_t *zonedb)
{
	uint16_t qtype = knot_pkt_qtype(query);
	uint16_t qclass = knot_pkt_qclass(query);
	const knot_dname_t *qname = knot_pkt_qname(query);
	const zone_t *zone = NULL;

	// search for zone only for IN and ANY classes
	if (qclass != KNOT_CLASS_IN && qclass != KNOT_CLASS_ANY) {
		return NULL;
	}

	/* In case of DS query, we strip the leftmost label when searching for
	 * the zone (but use whole qname in search for the record), as the DS
	 * records are only present in a parent zone.
	 */
	if (qtype == KNOT_RRTYPE_DS) {
		const knot_dname_t *parent = knot_wire_next_label(qname, NULL);
		zone = knot_zonedb_find_suffix(zonedb, parent);
		/* If zone does not exist, search for its parent zone,
		   this will later result to NODATA answer. */
		/*! \note This is not 100% right, it may lead to DS name for example
		 *        when following a CNAME chain, that should also be answered
		 *        from the parent zone (if it exists).
		 */
	}

	if (zone == NULL) {
		if (knot_pkt_type(query) == KNOT_QUERY_NORMAL) {
			zone = knot_zonedb_find_suffix(zonedb, qname);
		} else {
			// Direct match required.
			zone = knot_zonedb_find(zonedb, qname);
		}
	}

	return zone;
}

/*! \brief Initialize response, sizes and find zone from which we're going to answer. */
static int prepare_answer(const knot_pkt_t *query, knot_pkt_t *resp, knot_process_t *ctx)
{
	struct query_data *qdata = QUERY_DATA(ctx);
	server_t *server = qdata->param->server;

	/* Initialize response. */
	int ret = knot_pkt_init_response(resp, query);
	if (ret != KNOT_EOK) {
		dbg_ns("%s: can't init response pkt (%d)\n", __func__, ret);
		return ret;
	}

	/* Query MUST carry a question. */
	const knot_dname_t *qname = knot_pkt_qname(query);
	if (qname == NULL) {
		dbg_ns("%s: query missing QNAME, FORMERR\n", __func__);
		qdata->rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}

	/* Convert query QNAME to lowercase, but keep original QNAME case.
	 * Already checked for absence of compression and length.
	 */
	memcpy(qdata->orig_qname, qname, query->qname_size);
	ret = knot_dname_to_lower((knot_dname_t *)qname);
	if (ret != KNOT_EOK) {
		dbg_ns("%s: can't convert QNAME to lowercase (%d)\n", __func__, ret);
		return ret;
	}

	/* Find zone for QNAME. */
	qdata->zone = answer_zone_find(query, server->zone_db);

	/* Update maximal answer size. */
	if (qdata->param->proc_flags & NS_QUERY_LIMIT_SIZE) {
		resp->max_size = KNOT_WIRE_MIN_PKTSIZE;
	}

	/* Check if EDNS is supported. */
	if (!knot_pkt_has_edns(query)) {
		return KNOT_EOK;
	}

	/* Check EDNS version and return BADVERS if not supported. */
	if (knot_edns_get_version(query->opt_rr) != KNOT_EDNS_VERSION) {
		dbg_ns("%s: unsupported EDNS version required.\n", __func__);
		qdata->rcode_ext = KNOT_EDNS_RCODE_BADVERS;
	}

	/* Reserve space for OPT RR in the packet. Using size of the server's
	 * OPT RR, because that's the maximum size (RDATA may or may not be
	 * used).
	 */
	uint16_t reserve_size = KNOT_EDNS_MIN_SIZE;
	if (knot_edns_has_nsid(query->opt_rr) && conf()->nsid_len > 0) {
		reserve_size += KNOT_EDNS_OPTION_HDRLEN + conf()->nsid_len;
	}
	ret = knot_pkt_reserve(resp, reserve_size);
	if (ret != KNOT_EOK) {
		dbg_ns("%s: can't reserve OPT RR in response (%d)\n", __func__, ret);
		return ret;
	}

	/* Get minimal supported size from EDNS(0). */
	uint16_t client_maxlen = knot_edns_get_payload(query->opt_rr);
	uint16_t server_maxlen = conf()->max_udp_payload;
	uint16_t min_edns = MIN(client_maxlen, server_maxlen);

	/* Update packet size limit. */
	if (qdata->param->proc_flags & NS_QUERY_LIMIT_SIZE) {
		resp->max_size =  MAX(resp->max_size, min_edns);
		dbg_ns("%s: packet size limit <= %zuB\n", __func__, resp->max_size);
	}

	/* In the response, always advertise server's maximum UDP payload. */

	return ret;
}

static int process_query_err(knot_pkt_t *pkt, knot_process_t *ctx)
{
	assert(pkt && ctx);
	struct query_data *qdata = QUERY_DATA(ctx);
	dbg_ns("%s: making error response, rcode = %d (TSIG rcode = %d)\n",
	       __func__, qdata->rcode, qdata->rcode_tsig);

	/* Initialize response from query packet. */
	knot_pkt_t *query = qdata->query;
	knot_pkt_init_response(pkt, query);

	/* If original QNAME is empty, Query is either unparsed or for root domain.
	 * Either way, letter case doesn't matter. */
	if (qdata->orig_qname[0] != '\0') {
		memcpy(pkt->wire + KNOT_WIRE_HEADER_SIZE,
		       qdata->orig_qname, query->qname_size);
	}

	/* Set RCODE. */
	knot_wire_set_rcode(pkt->wire, qdata->rcode);

	/* Transaction security (if applicable). */
	if (process_query_sign_response(pkt, qdata) != KNOT_EOK) {
		return NS_PROC_FAIL;
	}

	return NS_PROC_DONE;
}

/*!
 * \brief Apply rate limit.
 */
static int ratelimit_apply(int state, knot_pkt_t *pkt, knot_process_t *ctx)
{
	/* Check if rate limiting applies. */
	struct query_data *qdata = QUERY_DATA(ctx);
	server_t *server = qdata->param->server;
	if (server->rrl == NULL) {
		return state;
	}

	rrl_req_t rrl_rq = {0};
	rrl_rq.w = pkt->wire;
	rrl_rq.query = qdata->query;
	if (!EMPTY_LIST(qdata->wildcards)) {
		rrl_rq.flags = RRL_WILDCARD;
	}
	if (rrl_query(server->rrl, qdata->param->remote,
	              &rrl_rq, qdata->zone) == KNOT_EOK) {
		/* Rate limiting not applied. */
		return state;
	}

	/* Now it is slip or drop. */
	if (rrl_slip_roll(conf()->rrl_slip)) {
		/* Answer slips. */
		if (process_query_err(pkt, ctx) != KNOT_EOK) {
			return NS_PROC_FAIL;
		}
		knot_wire_set_tc(pkt->wire);
	} else {
		/* Drop answer. */
		pkt->size = 0;
	}

	return NS_PROC_DONE;
}

static int process_query_out(knot_pkt_t *pkt, knot_process_t *ctx)
{
	assert(pkt && ctx);
	struct query_data *qdata = QUERY_DATA(ctx);
	struct query_plan *plan = conf()->query_plan;
	struct query_step *step = NULL;

	rcu_read_lock();

	/* Check parse state. */
	knot_pkt_t *query = qdata->query;
	int next_state = NS_PROC_DONE;
	if (query->parsed < query->size) {
		dbg_ns("%s: incompletely parsed query, FORMERR\n", __func__);
		knot_pkt_clear(pkt);
		qdata->rcode = KNOT_RCODE_FORMERR;
		next_state = NS_PROC_FAIL;
		goto finish;
	}

	/*
	 * Preprocessing.
	 */

	int ret = prepare_answer(query, pkt, ctx);
	if (ret != KNOT_EOK) {
		next_state = NS_PROC_FAIL;
		goto finish;
	}

	/* Before query processing code. */
	if (plan) {
		WALK_LIST(step, plan->stage[QPLAN_BEGIN]) {
			next_state = step->process(next_state, pkt, qdata, step->ctx);
		}
	}

	/* Answer based on qclass. */
	switch (knot_pkt_qclass(pkt)) {
	case KNOT_CLASS_CH:
		next_state = query_chaos(pkt, ctx);
		break;
	case KNOT_CLASS_ANY:
	case KNOT_CLASS_IN:
		next_state = query_internet(pkt, ctx);
		break;
	default:
		qdata->rcode = KNOT_RCODE_REFUSED;
		next_state = NS_PROC_FAIL;
		break;
	}

	/*
	 * Postprocessing.
	 */

	/* Transaction security (if applicable). */
	if (next_state == NS_PROC_DONE || next_state == NS_PROC_FULL) {
		if (process_query_sign_response(pkt, qdata) != KNOT_EOK) {
			next_state = NS_PROC_FAIL;
		}
	}

finish:
	/* Default RCODE is SERVFAIL if not specified otherwise. */
	if (next_state == NS_PROC_FAIL && qdata->rcode == KNOT_RCODE_NOERROR) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
	}

	/* Rate limits (if applicable). */
	if (qdata->param->proc_flags & NS_QUERY_LIMIT_RATE) {
		next_state = ratelimit_apply(next_state, pkt, ctx);
	}

	/* After query processing code. */
	if (plan) {
		WALK_LIST(step, plan->stage[QPLAN_END]) {
			next_state = step->process(next_state, pkt, qdata, step->ctx);
		}
	}

	rcu_read_unlock();
	return next_state;
}

bool process_query_acl_check(list_t *acl, struct query_data *qdata)
{
	knot_pkt_t *query = qdata->query;
	const struct sockaddr_storage *query_source = qdata->param->remote;
	const knot_dname_t *key_name = NULL;
	knot_tsig_algorithm_t key_alg = KNOT_TSIG_ALG_NULL;

	/* Skip if already checked and valid. */
	if (qdata->sign.tsig_key != NULL) {
		return true;
	}

	/* Authenticate with NOKEY if the packet isn't signed. */
	if (query->tsig_rr) {
		key_name = query->tsig_rr->owner;
		key_alg = tsig_rdata_alg(query->tsig_rr);
	}
	conf_iface_t *match = acl_find(acl, query_source, key_name);

	/* Did not authenticate, no fitting rule found. */
	if (match == NULL || (match->key && match->key->algorithm != key_alg)) {
		dbg_ns("%s: no ACL match => NOTAUTH\n", __func__);
		qdata->rcode = KNOT_RCODE_NOTAUTH;
		qdata->rcode_tsig = KNOT_RCODE_BADKEY;
		return false;
	}

	/* Remember used TSIG key. */
	qdata->sign.tsig_key = match->key;
	return true;
}

int process_query_verify(struct query_data *qdata)
{
	knot_pkt_t *query = qdata->query;
	knot_sign_context_t *ctx = &qdata->sign;

	/* NOKEY => no verification. */
	if (query->tsig_rr == NULL) {
		return KNOT_EOK;
	}

	/* Keep digest for signing response. */
	/*! \note This memory will be rewritten for multi-pkt answers. */
	ctx->tsig_digest = (uint8_t *)tsig_rdata_mac(query->tsig_rr);
	ctx->tsig_digestlen = tsig_rdata_mac_length(query->tsig_rr);

	/* Checking query. */
	int ret = knot_tsig_server_check(query->tsig_rr, query->wire,
	                                 query->size, ctx->tsig_key);

	dbg_ns("%s: QUERY TSIG check result = %s\n", __func__, knot_strerror(ret));

	/* Evaluate TSIG check results. */
	switch(ret) {
	case KNOT_EOK:
		qdata->rcode = KNOT_RCODE_NOERROR;
		break;
	case KNOT_TSIG_EBADKEY:
		qdata->rcode = KNOT_RCODE_NOTAUTH;
		qdata->rcode_tsig = KNOT_RCODE_BADKEY;
		break;
	case KNOT_TSIG_EBADSIG:
		qdata->rcode = KNOT_RCODE_NOTAUTH;
		qdata->rcode_tsig = KNOT_RCODE_BADSIG;
		break;
	case KNOT_TSIG_EBADTIME:
		qdata->rcode = KNOT_RCODE_NOTAUTH;
		qdata->rcode_tsig = KNOT_RCODE_BADTIME;
		ctx->tsig_time_signed = tsig_rdata_time_signed(query->tsig_rr);
		break;
	case KNOT_EMALF:
		qdata->rcode = KNOT_RCODE_FORMERR;
		break;
	default:
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		break;
	}

	return ret;
}

/*! \brief Module implementation. */
static const knot_process_module_t PROCESS_QUERY_MODULE = {
	&process_query_begin,
	&process_query_reset,
	&process_query_finish,
	&process_query_in,
	&process_query_out,
	&process_query_err
};

const knot_process_module_t *process_query_get_module(void)
{
	return &PROCESS_QUERY_MODULE;
}
