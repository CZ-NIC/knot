/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/packet/pkt.h"
#include "libknot/mm_ctx.h"
#include "knot/nameserver/tsig_ctx.h"

/*!
 * \brief Layer processing states.
 *
 * Each state represents the state machine transition,
 * and determines readiness for the next action.
 */
typedef enum {
	KNOT_STATE_NOOP = 0,   //!< Invalid.
	KNOT_STATE_CONSUME,    //!< Consume data.
	KNOT_STATE_PRODUCE,    //!< Produce data.
	KNOT_STATE_RESET,      //!< Restart processing.
	KNOT_STATE_DONE,       //!< Finished.
	KNOT_STATE_FAIL,       //!< Error.
	KNOT_STATE_FINAL,      //!< Finished and finalized.
	KNOT_STATE_IGNORE,     //!< Data has been ignored.
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	KNOT_LAYER_STATE_ASYNC  = 100,    //!< The request needs to be async handled. Value should match KNOT_STATE_ASYNC.
#endif
} knot_layer_state_t;

#define knot_layer_active_state(state) ((state) == KNOT_STATE_PRODUCE || (state) == KNOT_STATE_FAIL)
#define knot_layer_send_state(state)   ((state) != KNOT_STATE_FAIL && (state) != KNOT_STATE_NOOP)

typedef struct knot_layer_api knot_layer_api_t;

/*! \brief Packet processing context. */
typedef struct {
	const knot_layer_api_t *api;  //!< Layer API.
	knot_mm_t *mm;                //!< Processing memory context. This memory is setup from the req to the layer when request is processed.
	knot_layer_state_t state;     //!< Processing state.
	void *data;                   //!< Module specific.
	tsig_ctx_t *tsig;             //!< TODO: remove
	unsigned flags;               //!< Custom flags.
} knot_layer_t;

#define knot_layer_clear_req_data(layer) { \
	(layer).mm = NULL;                     \
	(layer).state = KNOT_STATE_NOOP;       \
	(layer).data = NULL;                   \
	(layer).tsig = NULL;                   \
	(layer).flags = 0;                     \
}

/*! \brief Packet processing module API. */
struct knot_layer_api {
	int (*begin)(knot_layer_t *ctx, void *params);
	int (*reset)(knot_layer_t *ctx);
	int (*finish)(knot_layer_t *ctx);
	int (*consume)(knot_layer_t *ctx, knot_pkt_t *pkt);
	int (*produce)(knot_layer_t *ctx, knot_pkt_t *pkt);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	int (*set_async_state)(knot_layer_t *ctx, knot_pkt_t *pkt, int layer_state);
#endif
};

/*! \brief Helper for conditional layer call. */
#define LAYER_CALL(layer, func, ...) \
	assert(layer->api); \
	if (layer->api->func) { \
		layer->state = layer->api->func(layer, ##__VA_ARGS__); \
	}

/*!
 * \brief Initialize packet processing context.
 *
 * \param ctx Layer context.
 * \param mm  Memory context.
 * \param api Layer API.
 */
inline static void knot_layer_init(knot_layer_t *ctx, knot_mm_t *mm,
                                   const knot_layer_api_t *api)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->mm = mm;
	ctx->api = api;
	ctx->state = KNOT_STATE_NOOP;
}

/*!
 * \brief Prepare packet processing.
 *
 * \param ctx Layer context.
 * \param params Initialization params.
 */
inline static void knot_layer_begin(knot_layer_t *ctx, void *params)
{
	LAYER_CALL(ctx, begin, params);
}

/*!
 * \brief Reset current packet processing context.
 *
 * \param ctx Layer context.
 */
inline static void knot_layer_reset(knot_layer_t *ctx)
{
	LAYER_CALL(ctx, reset);
}

/*!
 * \brief Finish and close packet processing context.
 *
 * \param ctx Layer context.
 */
inline static void knot_layer_finish(knot_layer_t *ctx)
{
	LAYER_CALL(ctx, finish);
}

/*!
 * \brief Add more data to layer processing.
 *
 * \param ctx Layer context.
 * \param pkt Data packet.
 */
inline static void knot_layer_consume(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	LAYER_CALL(ctx, consume, pkt);
}

/*!
 * \brief Generate output from layer.
 *
 * \param ctx Layer context.
 * \param pkt Data packet.
 */
inline static void knot_layer_produce(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	LAYER_CALL(ctx, produce, pkt);
}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
/*!
 * \brief Set the state from layer.
 *
 * \param ctx Layer context.
 * \param pkt Data packet.
 * \param state State to be set.
 */
inline static void knot_layer_set_async_state(knot_layer_t *ctx, knot_pkt_t *pkt, int state)
{
	LAYER_CALL(ctx, set_async_state, pkt, ctx->state);
}
#endif
