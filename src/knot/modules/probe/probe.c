/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/macros.h"
#include "contrib/wire_ctx.h"
#include "contrib/time.h"
#include "knot/include/module.h"
#include "knot/conf/base.h"
#include "knot/conf/schema.h"
#include "knot/conf/conf.h"
#include "libknot/libknot.h"

#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define MOD_PREFIX      "\x06""prefix"
#define MOD_RATE_LIMIT  "\x0A""rate-limit"

#define PROBE_MAX_WINDOW_COUNT 5
#define PROBE_WINDOW_LEN_NSEC (1000000000L / 5L)
static int check_prefix(knotd_conf_check_args_t *args)
{
	if (strchr((const char *)args->data, '.') != NULL) {
		args->err_str = "dot '.' is not allowed";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

const yp_item_t probe_conf[] = {
	{ MOD_PREFIX,       YP_TSTR, YP_VSTR = { "kprobe-" },     YP_FNONE, { check_prefix } },
	{ MOD_RATE_LIMIT,   YP_TINT, YP_VINT = {0, INT64_MAX, 0} },
	{ NULL }
};

int probe_conf_check(knotd_conf_check_args_t *args)
{
	// Check type.
	knotd_conf_t type = knotd_conf_check_item(args, MOD_PREFIX);
	if (strlen(type.single.string) > KNOT_PROBE_PREFIX_MAXSIZE) {
		args->err_str = "prefix is too long";
		return KNOT_EINVAL;
	}
	return KNOT_EOK;
}

typedef struct {
	knot_probe_channel_t channel;
	struct timespec last;
	uint64_t tokens;
} probe_channel_ctx_t;

typedef struct probe_ctx {
	probe_channel_ctx_t *probes;
	size_t probe_count;
	uint64_t rate;
} probe_ctx_t;


static int ss_to_addr(knot_addr_t *addr, const struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET) {
		struct sockaddr_in *sa = (struct sockaddr_in *)ss;
		memcpy(addr->addr, &sa->sin_addr, sizeof(sa->sin_addr));
		addr->family = ss->ss_family;
		addr->port = sa->sin_port;
		return KNOT_EOK;
	}
	else if (ss->ss_family == AF_INET6) {
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ss;
		memcpy(addr->addr, &sa->sin6_addr, sizeof(sa->sin6_addr));
		addr->family = sa->sin6_family;
		addr->port = sa->sin6_port;
		return KNOT_EOK;
	}
	return KNOT_EINVAL;
}


static void store_edns_nsid(knot_probe_edns_t *dst, const knot_rrset_t *src) {
	assert(dst);

	if (src) {
		uint8_t *nsid = NULL, *destination = dst->nsid;
		while((nsid = knot_edns_get_option(src, KNOT_EDNS_OPTION_NSID, nsid)) != NULL) {
			size_t size = MIN(4 + ntohs(((uint16_t *)nsid)[1]), dst->nsid + sizeof(dst->nsid) - destination);
			memcpy(destination, nsid, size);
			destination += size;
		}
	}
}

static void store_edns_cs(knot_probe_edns_t *dst, const knot_edns_options_t *src)
{
	assert(dst);

	if (src && src->ptr[KNOT_EDNS_OPTION_CLIENT_SUBNET]) {
		size_t size = 4 + ntohs(((uint16_t *)src->ptr[KNOT_EDNS_OPTION_CLIENT_SUBNET])[1]);
		if (size > sizeof(dst->client_subnet)) {
			return;
		}
		memcpy(dst->client_subnet, src->ptr[KNOT_EDNS_OPTION_CLIENT_SUBNET], size);
	}
}

static uint64_t count_windows(const struct timespec *interval)
{
	/* window every 1/5th of second (5Hz) */
	return interval->tv_nsec / PROBE_WINDOW_LEN_NSEC + interval->tv_sec * 5;
}

static knotd_state_t transfer(knotd_state_t state, knot_pkt_t *pkt,
                              knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata);

	unsigned tid = qdata->params->thread_id;
	probe_ctx_t *p = knotd_mod_ctx(mod);

	probe_channel_ctx_t *ctx = &(p->probes[tid % p->probe_count]);
	/* packet rate restriction */
	if (p->rate) {
		struct timespec now = time_now();
		struct timespec diff = time_diff(&ctx->last, &now);
		uint64_t dt = MIN(count_windows(&diff), PROBE_MAX_WINDOW_COUNT);
		if (dt > 0) {/* Window moved */
			/* Store time of change floored to window resolution */
			ctx->last.tv_sec = now.tv_sec;
			ctx->last.tv_nsec = (now.tv_nsec / PROBE_WINDOW_LEN_NSEC) * PROBE_WINDOW_LEN_NSEC; 

			uint64_t dn = (dt * p->rate) / PROBE_MAX_WINDOW_COUNT;
			ctx->tokens = MIN(ctx->tokens + dn, p->rate); 
		}
		if (ctx->tokens == 0) {
			/* Drop */
			return state;
		}
		--ctx->tokens;
	}

	/* Prepare and send data */ 
	knot_probe_channel_t *probe = &(ctx->channel);
	
	const struct sockaddr_storage *src = qdata->params->remote;
	const struct sockaddr_storage *dst = qdata->params->server;
	
	knot_probe_data_t d;
	
	store_edns_nsid(&d.edns_opts, pkt->opt_rr);
	store_edns_cs(&d.edns_opts, qdata->query->edns_opts);
	strncpy((char *)d.dname, (const char *)knot_pkt_qname(pkt), sizeof(d.dname) - 1);

	struct tcp_info info = { 0 };
	socklen_t tcp_info_length = sizeof(info);
	if (getsockopt(qdata->params->socket, SOL_TCP, TCP_INFO, (void *)&info, &tcp_info_length) == 0) {
		d.tcp_rtt = info.tcpi_rtt;
	}

	ss_to_addr(&d.src, src);
	ss_to_addr(&d.dst, dst);

	memcpy(d.query_hdr, qdata->query->wire, sizeof(d.query_hdr));
	memcpy(d.response_hdr, pkt->wire, sizeof(d.response_hdr));

	knot_probe_channel_send(probe, (uint8_t *)&d, sizeof(d), 0);

	return state;
}

int probe_load(knotd_mod_t *mod)
{
	conf_val_t val = conf_get(conf(), C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&val, NULL);
	if (!rundir) {
		return KNOT_EINVAL;
	}

	knotd_conf_t mod_conf = knotd_conf_mod(mod, MOD_PREFIX);
	char prefix[KNOT_PROBE_PREFIX_MAXSIZE + 1];
	char *sep = rundir[strlen(rundir) - 1] != '/' ? "/" : "";
	if (snprintf(prefix, KNOT_PROBE_PREFIX_MAXSIZE, "%s%s%s", rundir, sep, mod_conf.single.string) > KNOT_PROBE_PREFIX_MAXSIZE) {
		free(rundir);
		return KNOT_EINVAL;
	}
	free(rundir);

	probe_ctx_t *p = (probe_ctx_t *)calloc(1, sizeof(*p));
	if (!p) {
		return KNOT_ENOMEM;
	}

	mod_conf = knotd_conf_mod(mod, MOD_RATE_LIMIT);
	p->rate = mod_conf.single.integer;

	if ((p->probe_count = conf()->cache.srv_bg_threads) == 0) {
		free(p);
		return KNOT_EINVAL;
	}

	p->probes = (probe_channel_ctx_t *)calloc(p->probe_count, sizeof(probe_channel_ctx_t));
	if (!p->probes) {
		free(p);
		return KNOT_ENOMEM;
	}
	int ret;
	for (probe_channel_ctx_t *it = p->probes; it < &p->probes[p->probe_count]; ++it) {
		if (unlikely((ret = knot_probe_channel_init(&it->channel, prefix, (it - p->probes))) != KNOT_EOK)) {
			for (--it; it >= p->probes; --it) { // On error close all previous sockets
				knot_probe_channel_close(&it->channel);
			}
			free(p->probes);
			free(p);
			return ret;
		}
	}

	knotd_mod_ctx_set(mod, p);

	return knotd_mod_hook(mod, KNOTD_STAGE_END, transfer);
}

void probe_unload(knotd_mod_t *mod)
{
	probe_ctx_t *p = (probe_ctx_t *)knotd_mod_ctx(mod);
	for (int i = 0; i < p->probe_count; ++i) {
		knot_probe_channel_close(&p->probes[i].channel);
	}
	free(p->probes);
	free(knotd_mod_ctx(mod));
	knotd_mod_ctx_set(mod, NULL);
}

KNOTD_MOD_API(probe, KNOTD_MOD_FLAG_SCOPE_GLOBAL | KNOTD_MOD_FLAG_OPT_CONF,
              probe_load, probe_unload, probe_conf, probe_conf_check);
