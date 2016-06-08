/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/libknot.h"
#include "knot/common/log.h"
#include "knot/nameserver/axfr.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/ixfr.h"
#include "knot/nameserver/notify.h"
#include "knot/nameserver/log.h"
#include "contrib/mempattern.h"

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
