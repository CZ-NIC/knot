/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/nameserver/process_answer.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/notify.h"
#include "knot/nameserver/ixfr.h"
#include "knot/nameserver/axfr.h"

static int noop(knot_pkt_t *pkt, knot_process_t *ctx)
{
	return NS_PROC_NOOP;
}

/*! \brief Module implementation. */
const knot_process_module_t _process_answer = {
        &process_answer_begin,
        &process_answer_reset,
        &process_answer_finish,
        &process_answer,
        &noop, /* No output */
        &noop  /* No error processing. */
};

/*! \brief Accessor to query-specific data. */
#define ANSWER_DATA(ctx) ((struct answer_data *)(ctx)->data)

static void answer_data_init(knot_process_t *ctx, void *module_param)
{
	/* Initialize persistent data. */
	struct answer_data *data = ANSWER_DATA(ctx);
	memset(data, 0, sizeof(struct answer_data));
	data->mm = &ctx->mm;
	data->param = module_param;
}

/*! \brief Answer is paired to query if MsgId and QUESTION matches. */
static bool is_answer_to_query(const knot_pkt_t *query, knot_pkt_t *answer)
{
	return knot_wire_get_id(query->wire) == knot_wire_get_id(answer->wire) &&
	       knot_pkt_qtype(query)  == knot_pkt_qtype(answer)  &&
	       knot_pkt_qclass(query) == knot_pkt_qclass(answer) &&
	       knot_dname_is_equal(knot_pkt_qname(query), knot_pkt_qname(answer));
}

int process_answer_begin(knot_process_t *ctx, void *module_param)
{
	/* Initialize context. */
	assert(ctx);
	ctx->type = NS_PROC_ANSWER_ID;
	ctx->data = mm_alloc(&ctx->mm, sizeof(struct answer_data));

	/* Initialize persistent data. */
	answer_data_init(ctx, module_param);

	/* Await packet. */
	return NS_PROC_MORE;
}

int process_answer_reset(knot_process_t *ctx)
{
	assert(ctx);

	/* Initialize persistent data. */
	answer_data_init(ctx, ANSWER_DATA(ctx)->param);

	/* Await packet. */
	return NS_PROC_MORE;
}

int process_answer_finish(knot_process_t *ctx)
{
	process_answer_reset(ctx);
	mm_free(&ctx->mm, ctx->data);
	ctx->data = NULL;

	return NS_PROC_NOOP;
}

/* \note Private helper for process_answer repetitive checks. */
#define ANSWER_REQUIRES(condition, ret) \
	if (!(condition)) { \
		knot_pkt_free(&pkt); \
		return ret; \
	}

int process_answer(knot_pkt_t *pkt, knot_process_t *ctx)
{
	assert(pkt && ctx);
	struct answer_data *data = ANSWER_DATA(ctx);

	/* Check parse state. */
	ANSWER_REQUIRES(pkt->parsed >= KNOT_WIRE_HEADER_SIZE, NS_PROC_FAIL);
	ANSWER_REQUIRES(pkt->parsed == pkt->size, NS_PROC_FAIL);
	/* Accept only responses. */
	ANSWER_REQUIRES(knot_wire_get_qr(pkt->wire), NS_PROC_NOOP);
	/* Check if we want answer paired to query. */
	const knot_pkt_t *query = data->param->query;
	ANSWER_REQUIRES(query == NULL || is_answer_to_query(query, pkt), NS_PROC_NOOP);
	/* Class specific answer processing. */
	ANSWER_REQUIRES(knot_pkt_qclass(pkt) == KNOT_CLASS_IN, NS_PROC_NOOP);

#warning TODO: check TSIG here?

	/* Call appropriate processing handler. */
	int next_state = NS_PROC_NOOP;
	switch(knot_pkt_type(pkt)) {
	case KNOT_RESPONSE_NORMAL:
		next_state = internet_process_answer(pkt, data);
		break;
	case KNOT_RESPONSE_AXFR:
		next_state = axfr_process_answer(pkt, data);
		break;
	case KNOT_RESPONSE_IXFR:
		next_state = ixfrin_process_answer(pkt, data);
		break;
	case KNOT_RESPONSE_NOTIFY:
		next_state = notify_process_answer(pkt, data);
		break;
	default:
		next_state = NS_PROC_NOOP;
		break;
	}

	knot_pkt_free(&pkt);
	return next_state;
}

#undef ANSWER_REQUIRES
