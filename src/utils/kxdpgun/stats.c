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

pthread_mutex_t stdout_mtx = PTHREAD_MUTEX_INITIALIZER;

void clear_stats(kxdpgun_stats_t *st)
{
	pthread_mutex_lock(&st->mutex);
	st->since       = 0;
	st->until       = 0;
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
	into->since = what->since;
	collect_periodic_stats(into, what);
	size_t res = ++into->collected;
	pthread_mutex_unlock(&into->mutex);
	return res;
}

void collect_periodic_stats(kxdpgun_stats_t *into, const kxdpgun_stats_t *what)
{
	into->until        = what->until;
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
}

void plain_stats_header(const xdp_gun_ctx_t *ctx)
{
	INFO2("using interface %s, XDP threads %u, IPv%c/%s%s%s, %s mode", ctx->dev, ctx->n_threads,
	      (ctx->ipv6 ? '6' : '4'),
	      (ctx->tcp ? "TCP" : ctx->quic ? "QUIC" : "UDP"),
	      (ctx->sending_mode[0] != '\0' ? " mode " : ""),
	      (ctx->sending_mode[0] != '\0' ? ctx->sending_mode : ""),
	      (knot_eth_xdp_mode(if_nametoindex(ctx->dev)) == KNOT_XDP_MODE_FULL ? "native" : "emulated"));
	puts(STATS_SECTION_SEP);
}

/* see:
 * - https://github.com/DNS-OARC/dns-metrics/blob/main/dns-metrics.schema.json
 * - https://github.com/DNS-OARC/dns-metrics/issues/16#issuecomment-2139462920
 */
void json_stats_header(const xdp_gun_ctx_t *ctx)
{
	jsonw_t *w = ctx->jw;

	jsonw_object(w, NULL);
	{
		jsonw_ulong(w, "runid", ctx->runid);
		jsonw_str(w, "type", "header");
		jsonw_int(w, "schema_version", STATS_SCHEMA_VERSION);
		jsonw_str(w, "generator", PROGRAM_NAME);
		jsonw_str(w, "generator_version", PACKAGE_VERSION);

		jsonw_list(w, "generator_params");
		{
			for (char **it = ctx->argv; *it != NULL; ++it) {
				jsonw_str(w, NULL, *it);
			}
		}
		jsonw_end(w);

		jsonw_ulong(w, "time_units_per_sec", 1000000000);
		if (ctx->stats_period_ns > 0) {
			jsonw_double(w, "stats_interval", ctx->stats_period_ns / 1000000000.0);
		}
		// TODO: timeout

		// mirror the info given by the plaintext printout
		jsonw_object(w, "additional_info");
		{
			jsonw_str(w, "interface", ctx->dev);
			jsonw_int(w, "xdp_threads", ctx->n_threads);
			jsonw_int(w, "ip_version", ctx->ipv6 ? 6 : 4);
			jsonw_str(w, "transport_layer_proto", ctx->tcp ? "TCP" : (ctx->quic ? "QUIC" : "UDP"));
			jsonw_object(w, "mode_info");
			{
				if (ctx->sending_mode[0] != '\0') {
					jsonw_str(w, "debug", ctx->sending_mode);
				}
				jsonw_str(w, "mode", knot_eth_xdp_mode(if_nametoindex(ctx->dev)) == KNOT_XDP_MODE_FULL
							? "native"
							: "emulated");
			}
			jsonw_end(w);
		}
		jsonw_end(w);
	}
	jsonw_end(w);
}

void plain_thrd_summary(const xdp_gun_ctx_t *ctx, const kxdpgun_stats_t *st)
{
	pthread_mutex_lock(&stdout_mtx);

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

	pthread_mutex_unlock(&stdout_mtx);
}

void json_thrd_summary(const xdp_gun_ctx_t *ctx, const kxdpgun_stats_t *st)
{
	pthread_mutex_lock(&stdout_mtx);

	jsonw_t *w = ctx->jw;

	jsonw_object(ctx->jw, NULL);
	{
		jsonw_str(w, "type", "thread_summary");
		jsonw_ulong(w, "runid", ctx->runid);
		jsonw_ulong(w, "subid", ctx->thread_id);
		jsonw_ulong(w, "qry_sent", st->qry_sent);
		jsonw_ulong(w, "ans_recv", st->ans_recv);
		jsonw_ulong(w, "lost", st->lost);
		jsonw_ulong(w, "errors", st->errors);
	}
	jsonw_end(ctx->jw);

	pthread_mutex_unlock(&stdout_mtx);
}

void plain_stats(const xdp_gun_ctx_t *ctx, kxdpgun_stats_t *st, stats_type_t stt)
{
	pthread_mutex_lock(&st->mutex);

	printf("%s metrics:\n", (stt == STATS_SUM) ? "cumulative" : "periodic");

	bool recv = !(ctx->flags & KNOT_XDP_FILTER_DROP);
	uint64_t duration = DURATION_US(*st);
	double rel_start_us = (st->since / 1000.0) - ctx->stats_start_us ;
	double rel_end_us = rel_start_us + duration;

#define ps(counter)  ((typeof(counter))((counter) * 1000 / ((float)duration / 1000)))
#define pct(counter) ((counter) * 100.0 / st->qry_sent)

	const char *name = ctx->tcp ? "SYNs:    " : ctx->quic ? "initials:" : "queries: ";
	printf("total %s    %"PRIu64" (%"PRIu64" pps) (%f%%)\n", name, st->qry_sent,
	       ps(st->qry_sent), 100.0 * st->qry_sent / (duration / 1000000.0 * ctx->qps * ctx->n_threads));
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
	if (stt == STATS_SUM) {
		printf("duration: %.4f s\n", duration / 1000000.0);
	} else {
		printf("since: %.4fs   until: %.4fs\n", rel_start_us / 1000000, rel_end_us / 1000000);
	}

	pthread_mutex_unlock(&st->mutex);
}

/* see https://github.com/DNS-OARC/dns-metrics/blob/main/dns-metrics.schema.json
 * and https://github.com/DNS-OARC/dns-metrics/issues/16#issuecomment-2139462920 */
void json_stats(const xdp_gun_ctx_t *ctx, kxdpgun_stats_t *st, stats_type_t stt)
{
	assert(stt == STATS_PERIODIC || stt == STATS_SUM);

	jsonw_t *w = ctx->jw;

	pthread_mutex_lock(&st->mutex);

	jsonw_object(w, NULL);
	{
		jsonw_ulong(w, "runid", ctx->runid);
		jsonw_str(w, "type", (stt == STATS_PERIODIC) ? "stats_periodic" : "stats_sum");
		jsonw_ulong(w, "since", st->since);
		jsonw_ulong(w, "until", st->until);
		jsonw_ulong(w, "queries", st->qry_sent);
		jsonw_ulong(w, "responses", st->ans_recv);

		jsonw_object(w, "response_rcodes");
		{
			for (size_t i = 0; i < RCODE_MAX; ++i) {
				if (st->rcodes_recv[i] > 0) {
					const knot_lookup_t *rc = knot_lookup_by_id(knot_rcode_names, i);
					jsonw_ulong(w, (rc == NULL) ? "unknown" : rc->name, st->rcodes_recv[i]);
				}
			}
		}
		jsonw_end(w);

		jsonw_object(w, "conn_info");
		{
			jsonw_str(w, "type", ctx->tcp ? "tcp" : (ctx->quic ? "quic_conn" : "udp"));

			// TODO:
			// packets_sent
			// packets_recieved

			jsonw_ulong(w, "socket_errors", st->errors);
			if (ctx->tcp || ctx->quic) {
				jsonw_ulong(w, "handshakes", st->synack_recv);
				// TODO: handshakes_failed
				if (ctx->quic) {
					// TODO: conn_resumption
				}
			}
		}
		jsonw_end(w);
	}
	jsonw_end(w);

	pthread_mutex_unlock(&st->mutex);
}
