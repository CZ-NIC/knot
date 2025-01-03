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

/*!
 * \brief Initialize CTL thread processing contexts.
 *
 * \param concurrent_ctxs    Structures to initialize.
 * \param n_ctxs             Their number/count.
 * \param server             Server structure.
 */
void ctl_init_ctxs(concurrent_ctl_ctx_t *concurrent_ctxs, size_t n_ctxs, server_t *server);

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
 * Find/create a thread processing incomming control commands.
 *
 * \param[in]       ctl         Control context.
 * \param[in]       server      Server instance.
 * \param[in/out]   exclusive   CTLs are being processed exclusively by calling thread.
 * \param[in]       thread_idx  Calling thread index.
 * \param[in]       ctxs        CTL thread contexts.
 * \param[in]       n_ctxs      Number of CTL thread contexts.
 *
 * \return Error code, KNOT_EOK if successful, KNOT_CTL_ESTOP if server shutdown desired.
 */
int ctl_manage(knot_ctl_t *ctl, server_t *server, bool *exclusive,
               int thread_idx, concurrent_ctl_ctx_t *ctxs, size_t n_ctxs);
