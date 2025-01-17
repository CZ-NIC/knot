/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
	int thrs_per_sock;
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

/*!
 * \brief Initialize CTL socket handling threads.
 *
 * \param ctx     Socket thread contexts.
 * \param n_ctls  Number of socket threads.
 *
 * \return KNOT_E*
 */
int ctl_socket_thr_init(ctl_socket_ctx_t *ctx, size_t n_ctls);

/*!
 * \brief De-initialize CTL socket handling thread.
 *
 * \param ctx     Socket thread context.
 */
void ctl_socket_thr_end(ctl_socket_ctx_t *ctx);
