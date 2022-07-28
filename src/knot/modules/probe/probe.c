/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>
#include <stdint.h>

#include "knot/conf/schema.h"
#include "knot/include/module.h"
#include "contrib/string.h"
#include "contrib/time.h"
#include "libknot/libknot.h"

#ifdef HAVE_ATOMIC
#define ATOMIC_SET(dst, val) __atomic_store_n(&(dst), (val), __ATOMIC_RELAXED)
#define ATOMIC_GET(src)      __atomic_load_n(&(src), __ATOMIC_RELAXED)
#else
#define ATOMIC_SET(dst, val) ((dst) = (val))
#define ATOMIC_GET(src)      (src)
#endif

#define MOD_PATH       "\x04""path"
#define MOD_CHANNELS   "\x08""channels"
#define MOD_MAX_RATE   "\x08""max-rate"

const yp_item_t probe_conf[] = {
	{ MOD_PATH,     YP_TSTR, YP_VNONE },
	{ MOD_CHANNELS, YP_TINT, YP_VINT = { 1, UINT16_MAX, 1 } },
	{ MOD_MAX_RATE, YP_TINT, YP_VINT = { 0, UINT32_MAX, 100000 } },
	{ NULL }
};

typedef struct {
	knot_probe_t **probes;
	size_t probe_count;
	uint64_t *last_times;
	uint64_t min_diff_ns;
	char *path;
} probe_ctx_t;

static void free_probe_ctx(probe_ctx_t *ctx)
{
	for (int i = 0; ctx->probes != NULL && i < ctx->probe_count; ++i) {
		knot_probe_free(ctx->probes[i]);
	}
	free(ctx->probes);
	free(ctx->last_times);
	free(ctx->path);
	free(ctx);
}

static knotd_state_t export(knotd_state_t state, knot_pkt_t *pkt,
                            knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata);

	probe_ctx_t *ctx = knotd_mod_ctx(mod);
	uint16_t idx = qdata->params->thread_id % ctx->probe_count;
	knot_probe_t *probe = ctx->probes[idx];

	// Check the rate limit.
	struct timespec now = time_now();
	uint64_t now_ns = 1000000000 * now.tv_sec + now.tv_nsec;
	uint64_t last_ns = ATOMIC_GET(ctx->last_times[idx]);
	if (now_ns - last_ns < ctx->min_diff_ns) {
		return state;
	}
	ATOMIC_SET(ctx->last_times[idx], now_ns);

	// Prepare data sources.
	struct sockaddr_storage buff;
	const struct sockaddr_storage *local = knotd_qdata_local_addr(qdata, &buff);
	const struct sockaddr_storage *remote = knotd_qdata_remote_addr(qdata);

	knot_probe_proto_t proto = (knot_probe_proto_t)qdata->params->proto;
	const knot_pkt_t *reply = (state != KNOTD_STATE_NOOP ? pkt : NULL);

	uint16_t rcode = qdata->rcode;
	if (qdata->rcode_tsig != KNOT_RCODE_NOERROR) {
		rcode = qdata->rcode_tsig;
	}

	// Fill out and export the data structure.
	knot_probe_data_t d;
	int ret = knot_probe_data_set(&d, proto, local, remote, qdata->query, reply, rcode);
	if (ret == KNOT_EOK) {
		d.tcp_rtt = knotd_qdata_rtt(qdata);
		if (qdata->query->opt_rr != NULL) {
			d.reply.ede = qdata->rcode_ede;
		}
		(void)knot_probe_produce(probe, &d, 1);
	}

	return state;
}

int probe_load(knotd_mod_t *mod)
{
	probe_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	knotd_conf_t conf = knotd_conf_mod(mod, MOD_CHANNELS);
	ctx->probe_count = conf.single.integer;

	conf = knotd_conf_mod(mod, MOD_PATH);
	if (conf.count == 0) {
		conf = knotd_conf(mod, C_SRV, C_RUNDIR, NULL);
	}
	if (conf.single.string[0] != '/') {
		char *cwd = realpath("./", NULL);
		ctx->path = sprintf_alloc("%s/%s", cwd, conf.single.string);
		free(cwd);
	} else {
		ctx->path = strdup(conf.single.string);
	}
	if (ctx->path == NULL) {
		free_probe_ctx(ctx);
		return KNOT_ENOMEM;
	}

	ctx->probes = calloc(ctx->probe_count, sizeof(knot_probe_t *));
	if (ctx->probes == NULL) {
		free_probe_ctx(ctx);
		return KNOT_ENOMEM;
	}

	ctx->last_times = calloc(ctx->probe_count, sizeof(uint64_t));
	if (ctx->last_times == NULL) {
		free_probe_ctx(ctx);
		return KNOT_ENOMEM;
	}

	ctx->min_diff_ns = 0;
	conf = knotd_conf_mod(mod, MOD_MAX_RATE);
	if (conf.single.integer > 0) {
		ctx->min_diff_ns = ctx->probe_count * 1000000000 / conf.single.integer;
	}

	for (int i = 0; i < ctx->probe_count; i++) {
		knot_probe_t *probe = knot_probe_alloc();
		if (probe == NULL) {
			free_probe_ctx(ctx);
			return KNOT_ENOMEM;
		}

		int ret = knot_probe_set_producer(probe, ctx->path, i + 1);
		switch (ret) {
		case KNOT_ECONN:
			knotd_mod_log(mod, LOG_NOTICE, "channel %i not connected", i + 1);
		case KNOT_EOK:
			break;
		default:
			free_probe_ctx(ctx);
			return ret;
		}

		ctx->probes[i] = probe;
	}

	knotd_mod_ctx_set(mod, ctx);

	return knotd_mod_hook(mod, KNOTD_STAGE_END, export);
}

void probe_unload(knotd_mod_t *mod)
{
	probe_ctx_t *ctx = knotd_mod_ctx(mod);
	if (ctx != NULL) {
		free_probe_ctx(ctx);
	}
}

KNOTD_MOD_API(probe, KNOTD_MOD_FLAG_SCOPE_ANY | KNOTD_MOD_FLAG_OPT_CONF,
              probe_load, probe_unload, probe_conf, NULL);
