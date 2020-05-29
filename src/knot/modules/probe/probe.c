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
#include "knot/include/module.h"
#include "knot/nameserver/xfr.h" // Dependency on qdata->extra!
#include "libknot/libknot.h"

#define MOD_PREFIX	"\x06""prefix"


const yp_item_t probe_conf[] = {
	{ MOD_PREFIX,     YP_TSTR,  YP_VSTR  = { "/tmp/knot-probe-" } },
	{ NULL }
};

typedef struct {
	yp_name_t *conf_name;
	size_t conf_offset;
	uint32_t count;
	knotd_mod_idx_to_str_f fcn;
} ctr_desc_t;

struct probe_ctx {
	knot_probe_channel_wo_t *probes;
	size_t probe_count;
};

static knotd_state_t transfer(knotd_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata);

	unsigned tid = qdata->params->thread_id;
	struct probe_ctx *p = knotd_mod_ctx(mod);
	knot_probe_channel_wo_t *probe = &(p->probes[tid % p->probe_count]);
	
	const struct sockaddr_storage *src = qdata->params->remote;
	const struct sockaddr_storage *dst = qdata->params->server;
	knot_probe_datagram_t d = {
		.src.family = src->ss_family,
		.dst.family = dst->ss_family
	};
	if (src->ss_family == AF_INET) {
		struct sockaddr_in *sa = (struct sockaddr_in *)src;
		memcpy(d.src.addr, &sa->sin_addr, sizeof(sa->sin_addr));
		d.src.port = sa->sin_port;
	}
	else if (src->ss_family == AF_INET6) {
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)src;
		memcpy(d.src.addr, &sa->sin6_addr, sizeof(sa->sin6_addr));
		d.src.port = sa->sin6_port;
	}

	if (dst->ss_family == AF_INET) {
		struct sockaddr_in *sa = (struct sockaddr_in *)dst;
		memcpy(d.dst.addr, &sa->sin_addr, sizeof(sa->sin_addr));
		d.dst.port = sa->sin_port;
	}
	else if (dst->ss_family == AF_INET6) {
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)dst;
		memcpy(d.dst.addr, &sa->sin6_addr, sizeof(sa->sin6_addr));
		d.dst.port = sa->sin6_port;
	}
	//if (src->sin_addr == AF_INET) {
	//	memcpy(d.ip_src, (const uint8_t *)((struct sockaddr_in *)src)->sin_addr, sizeof(d.ip_src));
	//}
	//else if (src->sin_addr == AF_INET6) {
	//	memcpy(d.ip_src, src->sa_data, sizeof(d.ip_src));
	//}
	memcpy(d.dns_header, pkt->wire, sizeof(d.dns_header));

	knot_probe_channel_send(probe, (uint8_t *)&d, sizeof(d), 0);

	return state;
}

int probe_load(knotd_mod_t *mod)
{
	struct probe_ctx *p = (struct probe_ctx *)malloc(sizeof(*p));
	if (!p) {
		return KNOT_ENOMEM;
	}
	p->probe_count = 10;
	p->probes = (knot_probe_channel_wo_t *)calloc(p->probe_count, sizeof(knot_probe_channel_wo_t));
	if (!p->probes) {
		free (p);
		return KNOT_ENOMEM;
	}
	int ret;
	for (knot_probe_channel_wo_t *it = p->probes; it < &p->probes[p->probe_count]; ++it) {
		if (unlikely((ret = knot_probe_channel_wo_init(it, "/tmp/knot-probe-", (it - p->probes))) != KNOT_EOK)) {
			for (--it; it >= p->probes; --it) { // On error close all previous sockets
				knot_probe_channel_close(it);
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
	struct probe_ctx *p = (struct probe_ctx *)knotd_mod_ctx(mod);
	for (int i = 0; i < p->probe_count; ++i) {
		knot_probe_channel_close(&p->probes[i]);
	}
	free(p->probes);
	free(knotd_mod_ctx(mod));
	knotd_mod_ctx_set(mod, NULL);
}

KNOTD_MOD_API(probe, KNOTD_MOD_FLAG_SCOPE_GLOBAL | KNOTD_MOD_FLAG_OPT_CONF,
              probe_load, probe_unload, probe_conf, NULL);
