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

#include <string.h>
#include <urcu.h>

#include "contrib/threads.h"
#include "knot/ctl/threads.h"
#include "knot/server/signals.h"

void ctl_init_ctxs(concurrent_ctl_ctx_t *concurrent_ctxs, size_t n_ctxs,
                   server_t *server, int thr_idx_from)
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

static int ctl_socket_thr(struct dthread *dt)
{
	ctl_socket_ctx_t *ctx = dt->data;
	assert(dt == ctx->unit->threads[dt->idx]);

	concurrent_ctl_ctx_t concurrent_ctxs[ctx->thrs_per_sock - 1];
	ctl_init_ctxs(concurrent_ctxs, ctx->thrs_per_sock - 1, ctx->server,
	              dt->idx * ctx->thrs_per_sock);
	bool this_thread_exclusive = false;

	knot_ctl_t *my_ctl = ctx->ctls[dt->idx];

	while (dt->unit->threads[0]->state & ThreadActive) {
		if (ctl_cleanup_ctxs(concurrent_ctxs, ctx->thrs_per_sock - 1) == KNOT_CTL_ESTOP) {
			signals_req_stop = true;
			break;
		}

		// Update control timeout.
		knot_ctl_set_timeout(my_ctl, conf()->cache.ctl_timeout);

		int ret = knot_ctl_accept(my_ctl);
		if (ret != KNOT_EOK) {
			continue;
		}

		ret = ctl_manage(my_ctl, ctx->server, &this_thread_exclusive,
		                 dt->idx * ctx->thrs_per_sock, concurrent_ctxs,
		                 ctx->thrs_per_sock - 1);
		if (ret == KNOT_CTL_ESTOP) {
			signals_req_stop = true;
			break;
		}
	}

	ctl_finalize_ctxs(concurrent_ctxs, CTL_MAX_CONCURRENT);

	return 0;
}

int ctl_socket_thr_init(ctl_socket_ctx_t *ctx, size_t n_ctls)
{
	assert(n_ctls >= 1);

	dt_unit_t *dts = dt_create(n_ctls, ctl_socket_thr, NULL, ctx);
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
