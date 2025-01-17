/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/ctl/process.h"

typedef enum {
	CONCURRENT_EMPTY = 0,   // fresh cctx without a thread.
	CONCURRENT_ASSIGNED,    // cctx assigned to process a command.
	CONCURRENT_RUNNING,     // ctl command is being processed in the thread.
	CONCURRENT_IDLE,        // command has been processed, waiting for a new one.
	CONCURRENT_KILLED,      // cctx cleanup has started.
	CONCURRENT_FINISHED,    // after having been killed, the thread is being joined.
} concurrent_ctl_state_t;

typedef struct {
	concurrent_ctl_state_t state;
	pthread_mutex_t mutex;  // Protects .state.
	pthread_cond_t cond;
	knot_ctl_t *ctl;
	server_t *server;
	pthread_t thread;
	int ret;
	int thread_idx;
	bool exclusive;
} concurrent_ctl_ctx_t;

typedef struct {
	knot_ctl_t **ctls;
	server_t *server;
	dt_unit_t *unit;
	unsigned thr_count;
} ctl_socket_ctx_t;

/*!
 * \brief Initialize CTL thread processing contexts.
 *
 * \param concurrent_ctxs    Structures to initialize.
 * \param n_ctxs             Their number/count.
 * \param server             Server structure.
 * \param thr_idx_from       Base thread ID for sub-threads to start with.
 */
void ctl_init_ctxs(concurrent_ctl_ctx_t *concurrent_ctxs, size_t n_ctxs,
                   server_t *server, int thr_idx_from);

/*!
 * \brief Regularly check the state of parallel CTL processing workers.
 *
 * \param concurrent_ctxs    Parallel CTL processing contexts.
 * \param n_ctxs             Their number/count.
 *
 * \retval KNOT_ESTOP   Server shutdown requested.
 * \retval KNOT_EOK     Otherwise.
 */
int ctl_cleanup_ctxs(concurrent_ctl_ctx_t *concurrent_ctxs, size_t n_ctxs);

/*!
 * \brief De-initialize CTL thread processing contexts.
 *
 * \param concurrent_ctxs    Structures to de-initialize.
 * \param n_ctxs             Their number/count.
 */
void ctl_finalize_ctxs(concurrent_ctl_ctx_t *concurrent_ctxs, size_t n_ctxs);

/*!
 * \brief Initialize CTL socket handling threads.
 *
 * \param ctx         Socket thread contexts.
 * \param sock_count  Number of socket threads.
 *
 * \return KNOT_E*
 */
int ctl_socket_thr_init(ctl_socket_ctx_t *ctx, unsigned sock_count);

/*!
 * \brief De-initialize CTL socket handling threads.
 *
 * \param ctx     Socket thread context.
 */
void ctl_socket_thr_end(ctl_socket_ctx_t *ctx);
