#include <config.h>
#include <stdio.h>
#include <urcu.h>

#include "libknot/nameserver/ns_proc_query.h"
#include "libknot/consts.h"
#include "libknot/util/debug.h"
#include "libknot/nameserver/chaos.h"
#include "libknot/nameserver/internet.h"
#include "libknot/common.h"
#include "common/descriptor.h"

/* Forward decls. */
static int tsig_check(knot_pkt_t *pkt);
static const knot_zone_t *answer_zone_find(knot_pkt_t *pkt, knot_zonedb_t *zonedb);
static int prepare_answer(knot_pkt_t *query, knot_pkt_t *resp, ns_proc_context_t *ctx);
int query_internet(knot_pkt_t *pkt, ns_proc_context_t *ctx);
int query_chaos(knot_pkt_t *pkt, ns_proc_context_t *ctx);

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
	int ret = prepare_answer(data->pkt, pkt, ctx);
	if (ret != KNOT_EOK) {
		data->rcode = KNOT_RCODE_SERVFAIL;
		rcu_read_unlock();
		return NS_PROC_FAIL;
	} else {
		data->rcode = KNOT_RCODE_NOERROR;
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
		data->rcode = KNOT_RCODE_REFUSED;
		next_state = NS_PROC_FAIL;
		break;
	}

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
int query_internet(knot_pkt_t *pkt, ns_proc_context_t *ctx)
{
	struct query_data *data = QUERY_DATA(ctx);
	int next_state = NS_PROC_FAIL;

	/* Check zone validity. */
	switch(knot_zone_state(pkt->zone)) {
	case KNOT_EOK:     next_state = internet_answer(pkt, data); break;
	case KNOT_ENOENT:  data->rcode = KNOT_RCODE_REFUSED; break;
	default:           data->rcode = KNOT_RCODE_SERVFAIL; break;
	}

	return next_state;
}

/*!
 * \brief Create a response for a given query in the CHAOS class.
 */
int query_chaos(knot_pkt_t *pkt, ns_proc_context_t *ctx)
{
	dbg_ns("%s(%p, %p)\n", __func__, pkt, ctx);
	struct query_data *data = QUERY_DATA(ctx);

	data->rcode = knot_chaos_answer(pkt, ctx->ns);
	if (data->rcode != KNOT_RCODE_NOERROR) {
		dbg_ns("%s: failed with RCODE=%d\n", __func__, data->rcode);
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

static const knot_zone_t *answer_zone_find(knot_pkt_t *pkt, knot_zonedb_t *zonedb)
{
	uint16_t qtype = knot_pkt_qtype(pkt);
	uint16_t qclass = knot_pkt_qclass(pkt);
	const knot_dname_t *qname = knot_pkt_qname(pkt);

	// search for zone only for IN and ANY classes
	if (qclass != KNOT_CLASS_IN && qclass != KNOT_CLASS_ANY) {
		return NULL;
	}

	// find zone in which to search for the name
	return ns_get_zone_for_qname(zonedb, qname, qtype);
}

static int prepare_answer(knot_pkt_t *query, knot_pkt_t *resp, ns_proc_context_t *ctx)
{
	dbg_ns("%s(%p, %p, %p)\n", __func__, query, resp, ctx);

	int ret = knot_pkt_init_response(resp, query);
	if (ret != KNOT_EOK) {
		dbg_ns("%s: can't init response pkt (%d)\n", __func__, ret);
		return ret;
	}

	// find zone for qname
	resp->zone = answer_zone_find(query, ctx->ns->zone_db);

	/* Update maximal answer size. */
	if (!(ctx->flags & NS_PKTSIZE_NOLIMIT)) {
		resp->max_size = KNOT_WIRE_MIN_PKTSIZE;
	}

	/* Check if EDNS is supported. */
	if (!knot_pkt_have_edns(query)) {
		dbg_ns("%s: packet size limit %zuB\n", __func__, resp->max_size);
		return KNOT_EOK;
	}
	ret = knot_pkt_add_opt(resp, ctx->ns->opt_rr, knot_pkt_have_nsid(query));
	if (ret != KNOT_EOK) {
		dbg_ns("%s: can't add OPT RR (%d)\n", __func__, ret);
		return ret;
	}

	/* Copy DO bit if set (DNSSEC requested). */
	if (knot_pkt_have_dnssec(query)) {
		dbg_ns("%s: setting DO=1 in OPT RR\n", __func__);
		knot_edns_set_do(&(resp)->opt_rr);
	}
	/* Set minimal supported size from EDNS(0). */
	if (!(ctx->flags & NS_PKTSIZE_NOLIMIT)) {
		uint16_t client_maxlen = knot_edns_get_payload(&query->opt_rr);
		uint16_t server_maxlen = knot_edns_get_payload(&resp->opt_rr);
		resp->max_size = MAX(resp->max_size, MIN(client_maxlen, server_maxlen));
	}

	dbg_ns("%s: packet size limit %zuB\n", __func__, resp->max_size);
	return ret;
}
