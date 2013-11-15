#include <config.h>
#include <stdio.h>
#include <urcu.h>

#include "libknot/nameserver/ns_proc_query.h"
#include "common/descriptor.h"
#include "libknot/common.h"
#include "libknot/consts.h"
#include "libknot/util/debug.h"
#include "libknot/nameserver/chaos.h"

/* Forward decls. */
int answer_internet(knot_pkt_t *pkt, ns_proc_context_t *ctx);
int answer_chaos(knot_pkt_t *pkt, ns_proc_context_t *ctx);
static int tsig_check(knot_pkt_t *pkt);
static void find_query_zone(knot_pkt_t *pkt, knot_nameserver_t *ns);
static int prepare_answer(knot_pkt_t *query, knot_pkt_t *resp, knot_nameserver_t *ns);

/*! \brief Module implementation. */
const ns_proc_module_t _ns_proc_query = {
  &ns_proc_query_begin,
  &ns_proc_query_reset,
  &ns_proc_query_finish,
  &ns_proc_query_in,
  &ns_proc_query_out
};

struct query_data {
	int state;
	uint16_t rcode;
	uint16_t rcode_tsig;
	knot_pkt_t *pkt;
};

#define QUERY_DATA(ctx) ((struct query_data *)(ctx)->data)

int ns_proc_query_begin(ns_proc_context_t *ctx)
{
	/* Initialize context. */
	assert(ctx);
	ctx->type = NS_PROC_QUERY_ID;
	ctx->data = ctx->mm.alloc(ctx->mm.ctx, sizeof(struct query_data));
	memset(ctx->data, 0, sizeof(struct query_data));

	/* Await packet. */
	return NS_PROC_MORE;
}

int ns_proc_query_reset(ns_proc_context_t *ctx)
{
	/* Clear */
	assert(ctx);
	struct query_data *data = QUERY_DATA(ctx);
	knot_pkt_free(&data->pkt);
	memset(data, 0, sizeof(struct query_data));

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

	/* Answer from qclass. */
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

	/* Servfail error, make synthetic response. */
	if (data->rcode != KNOT_RCODE_SERVFAIL) {
		/*! \todo Better response for parsed packets. */
	}

	/* Clear packet. */
	knot_pkt_clear(pkt);

	/* Copy MsgId, opcode and RD bit. Set RCODE. */
	knot_pkt_t *query = data->pkt;
	knot_wire_set_id(pkt->wire, knot_wire_get_id(query->wire));
	knot_wire_set_opcode(pkt->wire, knot_wire_get_opcode(query->wire));
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
	return NS_PROC_FAIL;
}

/*!
 * \brief Create a response for a given query in the CHAOS class.
 */
int answer_chaos(knot_pkt_t *pkt, ns_proc_context_t *ctx)
{
	struct query_data *data = QUERY_DATA(ctx);
	data->rcode = knot_chaos_answer(pkt, ctx->ns);
	if (data->rcode == KNOT_RCODE_NOERROR) {
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

static void find_query_zone(knot_pkt_t *pkt, knot_nameserver_t *ns)
{
	uint16_t qtype = knot_pkt_qtype(pkt);
	uint16_t qclass = knot_pkt_qclass(pkt);
	const knot_dname_t *qname = knot_pkt_qname(pkt);

	// search for zone only for IN and ANY classes
	if (qclass != KNOT_CLASS_IN && qclass != KNOT_CLASS_ANY) {
		return;
	}

	// find zone in which to search for the name
	knot_zonedb_t *zonedb = rcu_dereference(ns->zone_db);
	pkt->zone = ns_get_zone_for_qname(zonedb, qname, qtype);
}

static int prepare_answer(knot_pkt_t *query, knot_pkt_t *resp, knot_nameserver_t *ns)
{
	dbg_ns("%s(%p, %p, %p)\n", __func__, query, resp, ns);

	int ret = knot_pkt_init_response(resp, query);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// find zone for qname
	find_query_zone(query, ns);

	/* Check if EDNS is supported. */
	if (!knot_pkt_have_edns(query)) {
		return KNOT_EOK;
	}

	// set the OPT RR to the response
	ret = knot_pkt_add_opt(resp, ns->opt_rr, knot_pkt_have_nsid(query));
	if (ret == KNOT_EOK) {
		// copy the DO bit from the query
		if (knot_pkt_have_dnssec(query)) {
			knot_edns_set_do(&(resp)->opt_rr);
		}

	}

	return ret;
}

