/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <urcu.h>

#include "contrib/threads.h"
#include "knot/ctl/threads.h"
#include "knot/server/signals.h"

void ctl_init_ctxs(concurrent_ctl_ctx_t *concurrent_ctxs, size_t n_ctxs, server_t *server)
{
	for (size_t i = 0; i < n_ctxs; i++) {
		concurrent_ctl_ctx_t *cctx = &concurrent_ctxs[i];
		pthread_mutex_init(&cctx->mutex, NULL);
		pthread_cond_init(&cctx->cond, NULL);
		cctx->server = server;
		cctx->thread_idx = i + 1;
	}
}

int ctl_cleanup_ctxs(concurrent_ctl_ctx_t *concurrent_ctxs, size_t n_ctxs)
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

void ctl_finalize_ctxs(concurrent_ctl_ctx_t *concurrent_ctxs, size_t n_ctxs)
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

int ctl_manage(knot_ctl_t *ctl, server_t *server, bool *exclusive,
               int thread_idx, concurrent_ctl_ctx_t *ctxs, size_t n_ctxs)
{
	int ret = KNOT_EOK;
	if (*exclusive || find_free_ctx(ctxs, n_ctxs, ctl) == NULL) {
		ret = ctl_process(ctl, server, thread_idx, exclusive);
		knot_ctl_close(ctl);
	}
	return ret;
}
