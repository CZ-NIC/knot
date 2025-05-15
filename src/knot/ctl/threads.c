/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <signal.h>
#include <string.h>
#include <urcu.h>

#include "contrib/threads.h"
#include "knot/ctl/threads.h"
#include "knot/server/signals.h"

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
	unsigned thread_idx;
	bool exclusive;
} concurrent_ctl_ctx_t;

static void ctl_init_ctxs(concurrent_ctl_ctx_t *concurrent_ctxs, size_t n_ctxs,
                          server_t *server, unsigned thr_idx_from)
{
	for (size_t i = 0; i < n_ctxs; i++) {
		concurrent_ctl_ctx_t *cctx = &concurrent_ctxs[i];
		memset(cctx, 0, sizeof(*cctx));
		pthread_mutex_init(&cctx->mutex, NULL);
		pthread_cond_init(&cctx->cond, NULL);
		cctx->server = server;
		cctx->thread_idx = thr_idx_from + i + 1;
	}
}

static int ctl_cleanup_ctxs(concurrent_ctl_ctx_t *concurrent_ctxs, size_t n_ctxs)
{
	int ret = KNOT_EOK;
	for (size_t i = 0; i < n_ctxs; i++) {
		concurrent_ctl_ctx_t *cctx = &concurrent_ctxs[i];
		pthread_mutex_lock(&cctx->mutex);
		if (cctx->state == CONCURRENT_IDLE) {
			knot_ctl_free(cctx->ctl);
			cctx->ctl = NULL;
			if (cctx->ret == KNOT_CTL_ESTOP) {
				ret = cctx->ret;
			}
		}
		pthread_mutex_unlock(&cctx->mutex);
	}
	return ret;
}

static void ctl_finalize_ctxs(concurrent_ctl_ctx_t *concurrent_ctxs, size_t n_ctxs)
{
	for (size_t i = 0; i < n_ctxs; i++) {
		concurrent_ctl_ctx_t *cctx = &concurrent_ctxs[i];
		pthread_mutex_lock(&cctx->mutex);
		if (cctx->state == CONCURRENT_EMPTY) {
			pthread_mutex_unlock(&cctx->mutex);
			pthread_mutex_destroy(&cctx->mutex);
			pthread_cond_destroy(&cctx->cond);
			continue;
		}

		cctx->state = CONCURRENT_KILLED;
		pthread_cond_broadcast(&cctx->cond);
		pthread_mutex_unlock(&cctx->mutex);
		(void)pthread_join(cctx->thread, NULL);

		assert(cctx->state == CONCURRENT_FINISHED);
		knot_ctl_free(cctx->ctl);
		pthread_mutex_destroy(&cctx->mutex);
		pthread_cond_destroy(&cctx->cond);
	}
}

static void *ctl_process_thread(void *arg)
{
	concurrent_ctl_ctx_t *ctx = arg;
	rcu_register_thread();
	signals_setup(); // in fact, this blocks common signals so that they
	                 // arrive to main thread instead of this one

	pthread_mutex_lock(&ctx->mutex);
	while (ctx->state != CONCURRENT_KILLED) {
		if (ctx->state != CONCURRENT_ASSIGNED) {
			pthread_cond_wait(&ctx->cond, &ctx->mutex);
			continue;
		}
		ctx->state = CONCURRENT_RUNNING;
		bool exclusive = ctx->exclusive;
		pthread_mutex_unlock(&ctx->mutex);

		// Not IDLE, ctx can be read without locking.
		int ret = ctl_process(ctx->ctl, ctx->server, ctx->thread_idx, &exclusive);

		pthread_mutex_lock(&ctx->mutex);
		ctx->ret = ret;
		ctx->exclusive = exclusive;
		if (ctx->state == CONCURRENT_RUNNING) { // not KILLED
			ctx->state = CONCURRENT_IDLE;
			pthread_cond_broadcast(&ctx->cond);
		}
	}

	knot_ctl_close(ctx->ctl);

	ctx->state = CONCURRENT_FINISHED;
	pthread_mutex_unlock(&ctx->mutex);
	rcu_unregister_thread();
	return NULL;
}

static concurrent_ctl_ctx_t *find_free_ctx(concurrent_ctl_ctx_t *concurrent_ctxs,
                                           size_t n_ctxs, knot_ctl_t *ctl)
{
	concurrent_ctl_ctx_t *res = NULL;
	for (size_t i = 0; i < n_ctxs && res == NULL; i++) {
		concurrent_ctl_ctx_t *cctx = &concurrent_ctxs[i];
		pthread_mutex_lock(&cctx->mutex);
		if (cctx->exclusive) {
			while (cctx->state != CONCURRENT_IDLE) {
				pthread_cond_wait(&cctx->cond, &cctx->mutex);
			}
			if (cctx->ret == KNOT_CTL_ESTOP) {
				pthread_mutex_unlock(&cctx->mutex);
				return NULL;
			}
			knot_ctl_free(cctx->ctl);
			cctx->ctl = knot_ctl_clone(ctl);
			if (cctx->ctl == NULL) {
				cctx->exclusive = false;
				pthread_mutex_unlock(&cctx->mutex);
				break;
			}
			cctx->state = CONCURRENT_ASSIGNED;
			res = cctx;
			pthread_cond_broadcast(&cctx->cond);
		}
		pthread_mutex_unlock(&cctx->mutex);
	}
	for (size_t i = 0; i < n_ctxs && res == NULL; i++) {
		concurrent_ctl_ctx_t *cctx = &concurrent_ctxs[i];
		pthread_mutex_lock(&cctx->mutex);
		if (cctx->ret == KNOT_CTL_ESTOP) {
			pthread_mutex_unlock(&cctx->mutex);
			return NULL;
		}
		switch (cctx->state) {
		case CONCURRENT_EMPTY:
			(void)thread_create_nosignal(&cctx->thread, ctl_process_thread, cctx);
			break;
		case CONCURRENT_IDLE:
			knot_ctl_free(cctx->ctl);
			pthread_cond_broadcast(&cctx->cond);
			break;
		default:
			pthread_mutex_unlock(&cctx->mutex);
			continue;
		}
		cctx->ctl = knot_ctl_clone(ctl);
		if (cctx->ctl != NULL) {
			cctx->state = CONCURRENT_ASSIGNED;
			res = cctx;
		}
		pthread_mutex_unlock(&cctx->mutex);
	}
	return res;
}

static int ctl_socket_thr(struct dthread *dt)
{
	ctl_socket_ctx_t *ctx = dt->data;
	assert(dt == ctx->unit->threads[dt->idx]);

	unsigned sock_thr_count = ctx->thr_count - 1;
	unsigned thr_idx = dt->idx * ctx->thr_count;
	knot_ctl_t *thr_ctl = ctx->ctls[dt->idx];
	bool thr_exclusive = false, stopped = false;

	concurrent_ctl_ctx_t concurrent_ctxs[sock_thr_count];
	ctl_init_ctxs(concurrent_ctxs, sock_thr_count, ctx->server, thr_idx);

	while (dt->unit->threads[0]->state & ThreadActive) {
		if (ctl_cleanup_ctxs(concurrent_ctxs, sock_thr_count) == KNOT_CTL_ESTOP) {
			stopped = true;
			break;
		}

		knot_ctl_set_timeout(thr_ctl, conf()->cache.ctl_timeout);

		int ret = knot_ctl_accept(thr_ctl);
		if (ret != KNOT_EOK) {
			continue;
		}

		if (thr_exclusive ||
		    find_free_ctx(concurrent_ctxs, sock_thr_count, thr_ctl) == NULL) {
			ret = ctl_process(thr_ctl, ctx->server, thr_idx, &thr_exclusive);
			knot_ctl_close(thr_ctl);
		}
		if (ret == KNOT_CTL_ESTOP) {
			stopped = true;
			break;
		}
	}

	ctl_finalize_ctxs(concurrent_ctxs, sock_thr_count);

	if (stopped) {
		(void)kill(getpid(), SIGTERM);
	}

	return 0;
}

int ctl_socket_thr_init(ctl_socket_ctx_t *ctx, unsigned sock_count)
{
	if (sock_count == 0 || ctx->thr_count < 2) {
		return KNOT_EINVAL;
	}

	dt_unit_t *dts = dt_create(sock_count, ctl_socket_thr, NULL, ctx);
	if (dts == NULL) {
		return KNOT_ENOMEM;
	}
	ctx->unit = dts;
	return dt_start(dts);
}

void ctl_socket_thr_end(ctl_socket_ctx_t *ctx)
{
	(void)dt_stop(ctx->unit);
	(void)dt_join(ctx->unit);
	dt_delete(&ctx->unit);
}
