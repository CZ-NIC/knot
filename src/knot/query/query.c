/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdint.h>
#include <string.h>

// XXX: mempattern + mempool?

#include "contrib/mempattern.h"
#include "contrib/ucw/mempool.h"
#include "contrib/wire.h"
#include "dnssec/random.h"
#include "knot/query/query.h"
#include "knot/query/requestor.h"
#include "knot/zone/zone.h"
#include "libknot/mm_ctx.h"
#include "libknot/packet/pkt.h"
#include "libknot/yparser/yptrafo.h"

// XXX: temporary location of handlers
#include "knot/nameserver/axfr.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/ixfr.h"
#include "knot/nameserver/notify.h"

/*! \brief Accessor to query-specific data. */
#define ANSWER_DATA(ctx) ((struct answer_data *)(ctx)->data)
#define RESPONSE_TYPE_UNSET -1

static void answer_data_init(knot_layer_t *ctx, void *module_param)
{
	/* Initialize persistent data. */
	struct answer_data *data = ANSWER_DATA(ctx);
	memset(data, 0, sizeof(struct answer_data));
	data->response_type = RESPONSE_TYPE_UNSET;
	data->mm = ctx->mm;
	data->param = module_param;
}

/*! \brief Answer is paired to query if MsgId matches.
 *  @note Zone transfers are deliberate with QUESTION section and may not
 *        include it in multi-packet responses, therefore the response can be
 *        paired by MsgId only.
 */
static bool is_answer_to_query(const knot_pkt_t *query, knot_pkt_t *answer)
{
	return knot_wire_get_id(query->wire) == knot_wire_get_id(answer->wire);
}

static int process_answer_begin(knot_layer_t *ctx, void *module_param)
{
	/* Initialize context. */
	assert(ctx);
	ctx->data = mm_alloc(ctx->mm, sizeof(struct answer_data));

	/* Initialize persistent data. */
	answer_data_init(ctx, module_param);

	/* Issue the query. */
	return KNOT_STATE_PRODUCE;
}

static int process_answer_reset(knot_layer_t *ctx)
{
	assert(ctx);
	struct answer_data *data = ANSWER_DATA(ctx);

	/* Remember persistent parameters. */
	struct process_answer_param *module_param = data->param;

	/* Free allocated data. */
	if (data->ext_cleanup != NULL) {
		data->ext_cleanup(data);
	}

	/* Initialize persistent data. */
	answer_data_init(ctx, module_param);

	/* Issue the query. */
	return KNOT_STATE_PRODUCE;
}

static int process_answer_finish(knot_layer_t *ctx)
{
	process_answer_reset(ctx);
	mm_free(ctx->mm, ctx->data);
	ctx->data = NULL;

	return KNOT_STATE_NOOP;
}

/* \note Private helper for process_answer repetitive checks. */
#define ANSWER_REQUIRES(condition, ret) \
	if (!(condition)) { \
		knot_pkt_free(&pkt); \
		return ret; \
	}

static int process_answer(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct answer_data *data = ANSWER_DATA(ctx);

	/* Check parse state. */
	ANSWER_REQUIRES(pkt->parsed >= KNOT_WIRE_HEADER_SIZE, KNOT_STATE_FAIL);
	ANSWER_REQUIRES(pkt->parsed == pkt->size, KNOT_STATE_FAIL);
	/* Accept only responses. */
	ANSWER_REQUIRES(knot_wire_get_qr(pkt->wire), KNOT_STATE_NOOP);
	/* Check if we want answer paired to query. */
	const knot_pkt_t *query = data->param->query;
	if (!query) {
		return KNOT_STATE_FAIL;
	}
	ANSWER_REQUIRES(is_answer_to_query(query, pkt), KNOT_STATE_NOOP);

	/* Verify incoming packet. */
	int ret = tsig_verify_packet(&data->param->tsig_ctx, pkt);
	if (ret != KNOT_EOK) {
		// XXX: "response" operation sounds like placeholder
		NS_PROC_LOG(LOG_WARNING, data->param->zone->name, data->param->remote,
		            "response", "denied (%s)", knot_strerror(ret));
		return KNOT_STATE_FAIL;
	}

	/* Call appropriate processing handler. */
	int next_state = KNOT_STATE_NOOP;
	if (data->response_type == RESPONSE_TYPE_UNSET) {
		/* @note We can't derive type from response, as it may not contain QUESTION at all. */
		data->response_type = knot_pkt_type(query) | KNOT_RESPONSE;
	}
	switch(data->response_type) {
	case KNOT_RESPONSE_NORMAL:
		next_state = internet_process_answer(pkt, data);
		break;
	case KNOT_RESPONSE_AXFR:
		next_state = axfr_process_answer(pkt, data);
		break;
	case KNOT_RESPONSE_IXFR:
		next_state = ixfr_process_answer(pkt, data);
		break;
	case KNOT_RESPONSE_NOTIFY:
		next_state = notify_process_answer(pkt, data);
		break;
	default:
		next_state = KNOT_STATE_NOOP;
		break;
	}

	return next_state;
}
#undef ANSWER_REQUIRES

static int prepare_query(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	/* \note Don't touch the query, expect answer. */
	return KNOT_STATE_CONSUME;
}

/*! \brief Module implementation. */
const knot_layer_api_t *process_answer_layer(void)
{
	static const knot_layer_api_t api = {
		.begin = &process_answer_begin,
		.reset = &process_answer_reset,
		.finish = &process_answer_finish,
		.consume = &process_answer,
		.produce = &prepare_query,
	};
	return &api;
}



/*! \brief Create zone query packet. */
static knot_pkt_t *zone_query(const zone_t *zone, uint16_t pkt_type, knot_mm_t *mm)
{
	/* Determine query type and opcode. */
	uint16_t query_type = KNOT_RRTYPE_SOA;
	uint16_t opcode = KNOT_OPCODE_QUERY;
	switch(pkt_type) {
	case KNOT_QUERY_AXFR: query_type = KNOT_RRTYPE_AXFR; break;
	case KNOT_QUERY_IXFR: query_type = KNOT_RRTYPE_IXFR; break;
	case KNOT_QUERY_NOTIFY: opcode = KNOT_OPCODE_NOTIFY; break;
	}

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, mm);
	if (pkt == NULL) {
		return NULL;
	}

	knot_wire_set_id(pkt->wire, dnssec_random_uint16_t());
	knot_wire_set_opcode(pkt->wire, opcode);
	if (pkt_type == KNOT_QUERY_NOTIFY) {
		knot_wire_set_aa(pkt->wire);
	}

	knot_pkt_put_question(pkt, zone->name, KNOT_CLASS_IN, query_type);

	/* Put current SOA (optional). */
	zone_contents_t *contents = zone->contents;
	if (pkt_type == KNOT_QUERY_IXFR) {  /* RFC1995, SOA in AUTHORITY. */
		knot_pkt_begin(pkt, KNOT_AUTHORITY);
		knot_rrset_t soa_rr = node_rrset(contents->apex, KNOT_RRTYPE_SOA);
		knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &soa_rr, 0);
	} else if (pkt_type == KNOT_QUERY_NOTIFY) { /* RFC1996, SOA in ANSWER. */
		knot_pkt_begin(pkt, KNOT_ANSWER);
		knot_rrset_t soa_rr = node_rrset(contents->apex, KNOT_RRTYPE_SOA);
		knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &soa_rr, 0);
	}

	return pkt;
}

/*! \brief Set EDNS section. */
static int prepare_edns(conf_t *conf, zone_t *zone, knot_pkt_t *pkt)
{
	conf_val_t val = conf_zone_get(conf, C_REQUEST_EDNS_OPTION, zone->name);

	/* Check if an extra EDNS option is configured. */
	size_t opt_len;
	const uint8_t *opt_data = conf_data(&val, &opt_len);
	if (opt_data == NULL) {
		return KNOT_EOK;
	}

	knot_rrset_t opt_rr;
	conf_val_t *max_payload = &conf->cache.srv_max_udp_payload;
	int ret = knot_edns_init(&opt_rr, conf_int(max_payload), 0,
	                         KNOT_EDNS_VERSION, &pkt->mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_edns_add_option(&opt_rr, wire_read_u64(opt_data),
	                           yp_bin_len(opt_data + sizeof(uint64_t)),
	                           yp_bin(opt_data + sizeof(uint64_t)), &pkt->mm);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&opt_rr, &pkt->mm);
		return ret;
	}

	knot_pkt_begin(pkt, KNOT_ADDITIONAL);

	ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, &opt_rr, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&opt_rr, &pkt->mm);
		return ret;
	}

	return KNOT_EOK;
}

/*! \brief Process query using requestor. */
static int zone_query_request(knot_pkt_t *query, const conf_remote_t *remote,
                              struct process_answer_param *param, knot_mm_t *mm)
{
	/* Create requestor instance. */
	const knot_layer_api_t *api = process_answer_layer();
	struct knot_requestor re;
	int ret = knot_requestor_init(&re, api, param, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Create a request. */
	const struct sockaddr *dst = (const struct sockaddr *)&remote->addr;
	const struct sockaddr *src = (const struct sockaddr *)&remote->via;
	struct knot_request *req = knot_request_make(re.mm, dst, src, query, 0);
	if (req == NULL) {
		knot_requestor_clear(&re);
		return KNOT_ENOMEM;
	}

	/* Send the queries and process responses. */
	conf_val_t *val = &param->conf->cache.srv_tcp_reply_timeout;
	int timeout = conf_int(val) * 1000;
	ret = knot_requestor_exec(&re, req, timeout);

	/* Cleanup. */
	knot_request_free(req, re.mm);
	knot_requestor_clear(&re);

	return ret;
}

/*!
 * \brief Create a zone event query, send it, wait for the response and process it.
 *
 * \note Everything in this function is executed synchronously, returns when
 *       the query processing is either complete or an error occurs.
 */
int zone_query_execute(conf_t *conf, zone_t *zone, uint16_t pkt_type, const conf_remote_t *remote)
{
	/* Create a memory pool for this task. */
	knot_mm_t mm;
	mm_ctx_mempool(&mm, MM_DEFAULT_BLKSIZE);

	/* Create a query message. */
	knot_pkt_t *query = zone_query(zone, pkt_type, &mm);
	if (query == NULL) {
		mp_delete(mm.ctx);
		return KNOT_ENOMEM;
	}

	/* Set EDNS section. */
	int ret = prepare_edns(conf, zone, query);
	if (ret != KNOT_EOK) {
		knot_pkt_free(&query);
		mp_delete(mm.ctx);
		return ret;
	}

	/* Answer processing parameters. */
	struct process_answer_param param = {
		.zone = zone,
		.conf = conf,
		.query = query,
		.remote = &remote->addr
	};

	const knot_tsig_key_t *key = remote->key.name != NULL ?
	                             &remote->key : NULL;
	tsig_init(&param.tsig_ctx, key);

	ret = tsig_sign_packet(&param.tsig_ctx, query);
	if (ret != KNOT_EOK) {
		tsig_cleanup(&param.tsig_ctx);
		knot_pkt_free(&query);
		mp_delete(mm.ctx);
		return ret;
	}

	/* Process the query. */
	ret = zone_query_request(query, remote, &param, &mm);

	/* Cleanup. */
	tsig_cleanup(&param.tsig_ctx);
	knot_pkt_free(&query);
	mp_delete(mm.ctx);

	return ret;
}
