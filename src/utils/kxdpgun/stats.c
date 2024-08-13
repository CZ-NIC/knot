/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "contrib/macros.h"
#include "libknot/codes.h"
#include "libknot/lookup.h"
#include "utils/common/msg.h"
#include "utils/kxdpgun/main.h"
#include "utils/kxdpgun/stats.h"

void clear_stats(kxdpgun_stats_t *st)
{
	pthread_mutex_lock(&st->mutex);
	st->duration    = 0;
	st->qry_sent    = 0;
	st->synack_recv = 0;
	st->ans_recv    = 0;
	st->finack_recv = 0;
	st->rst_recv    = 0;
	st->size_recv   = 0;
	st->wire_recv   = 0;
	st->collected   = 0;
	st->lost        = 0;
	st->errors      = 0;
	memset(st->rcodes_recv, 0, sizeof(st->rcodes_recv));
	pthread_mutex_unlock(&st->mutex);
}

size_t collect_stats(kxdpgun_stats_t *into, const kxdpgun_stats_t *what)
{
	pthread_mutex_lock(&into->mutex);
	into->duration     = MAX(into->duration, what->duration);
	into->qry_sent    += what->qry_sent;
	into->synack_recv += what->synack_recv;
	into->ans_recv    += what->ans_recv;
	into->finack_recv += what->finack_recv;
	into->rst_recv    += what->rst_recv;
	into->size_recv   += what->size_recv;
	into->wire_recv   += what->wire_recv;
	into->lost        += what->lost;
	into->errors      += what->errors;
	for (int i = 0; i < RCODE_MAX; i++) {
		into->rcodes_recv[i] += what->rcodes_recv[i];
	}
	size_t res = ++into->collected;
	pthread_mutex_unlock(&into->mutex);
	return res;
}

void print_stats_header(const xdp_gun_ctx_t *ctx)
{
	INFO2("using interface %s, XDP threads %u, IPv%c/%s%s%s, %s mode", ctx->dev, ctx->n_threads,
	      (ctx->ipv6 ? '6' : '4'),
	      (ctx->tcp ? "TCP" : ctx->quic ? "QUIC" : "UDP"),
	      (ctx->sending_mode[0] != '\0' ? " mode " : ""),
	      (ctx->sending_mode[0] != '\0' ? ctx->sending_mode : ""),
	      (knot_eth_xdp_mode(if_nametoindex(ctx->dev)) == KNOT_XDP_MODE_FULL ? "native" : "emulated"));
}

void print_thrd_summary(const xdp_gun_ctx_t *ctx, const kxdpgun_stats_t *st)
{
	char recv_str[40] = "", lost_str[40] = "", err_str[40] = "";
	if (!(ctx->flags & KNOT_XDP_FILTER_DROP)) {
		(void)snprintf(recv_str, sizeof(recv_str), ", received %"PRIu64, st->ans_recv);
	}
	if (st->lost > 0) {
		(void)snprintf(lost_str, sizeof(lost_str), ", lost %"PRIu64, st->lost);
	}
	if (st->errors > 0) {
		(void)snprintf(err_str, sizeof(err_str), ", errors %"PRIu64, st->errors);
	}
	INFO2("thread#%02u: sent %"PRIu64"%s%s%s",
	      ctx->thread_id, st->qry_sent, recv_str, lost_str, err_str);
}

void print_stats(kxdpgun_stats_t *st, const xdp_gun_ctx_t *ctx)
{
	pthread_mutex_lock(&st->mutex);

	bool recv = !(ctx->flags & KNOT_XDP_FILTER_DROP);

#define ps(counter)  ((typeof(counter))((counter) * 1000 / ((float)st->duration / 1000)))
#define pct(counter) ((counter) * 100.0 / st->qry_sent)

	const char *name = ctx->tcp ? "SYNs:    " : ctx->quic ? "initials:" : "queries: ";
	printf("total %s    %"PRIu64" (%"PRIu64" pps) (%f%%)\n", name, st->qry_sent,
	       ps(st->qry_sent), 100.0 * st->qry_sent / (st->duration / 1000000.0 * ctx->qps * ctx->n_threads));
	if (st->qry_sent > 0 && recv) {
		if (ctx->tcp || ctx->quic) {
		name = ctx->tcp ? "established:" : "handshakes: ";
		printf("total %s %"PRIu64" (%"PRIu64" pps) (%f%%)\n", name,
		       st->synack_recv, ps(st->synack_recv), pct(st->synack_recv));
		}
		printf("total replies:     %"PRIu64" (%"PRIu64" pps) (%f%%)\n",
		       st->ans_recv, ps(st->ans_recv), pct(st->ans_recv));
		if (ctx->tcp) {
		printf("total closed:      %"PRIu64" (%"PRIu64" pps) (%f%%)\n",
		       st->finack_recv, ps(st->finack_recv), pct(st->finack_recv));
		}
		if (st->rst_recv > 0) {
		printf("total reset:       %"PRIu64" (%"PRIu64" pps) (%f%%)\n",
		       st->rst_recv, ps(st->rst_recv), pct(st->rst_recv));
		}
		printf("average DNS reply size: %"PRIu64" B\n",
		       st->ans_recv > 0 ? st->size_recv / st->ans_recv : 0);
		printf("average Ethernet reply rate: %"PRIu64" bps (%.2f Mbps)\n",
		       ps(st->wire_recv * 8), ps((float)st->wire_recv * 8 / (1000 * 1000)));

		for (int i = 0; i < RCODE_MAX; i++) {
			if (st->rcodes_recv[i] > 0) {
				const knot_lookup_t *rcode = knot_lookup_by_id(knot_rcode_names, i);
				const char *rcname = rcode == NULL ? "unknown" : rcode->name;
				int space = MAX(9 - strlen(rcname), 0);
				printf("responded %s: %.*s%"PRIu64"\n",
				       rcname, space, "         ", st->rcodes_recv[i]);
			}
		}
	}
	printf("duration: %"PRIu64" s\n", (st->duration / (1000 * 1000)));

	pthread_mutex_unlock(&st->mutex);
}
