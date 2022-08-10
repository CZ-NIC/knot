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

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include "libknot/libknot.h"
#include "libknot/xdp.h"
#include "libknot/xdp/tcp_iobuf.h"
#ifdef ENABLE_QUIC
#include <gnutls/gnutls.h>
#include "libknot/xdp/quic.h"
#endif // ENABLE_QUIC
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/os.h"
#include "contrib/sockaddr.h"
#include "contrib/toeplitz.h"
#include "contrib/ucw/mempool.h"
#include "utils/common/msg.h"
#include "utils/common/params.h"
#include "utils/kxdpgun/ip_route.h"
#include "utils/kxdpgun/load_queries.h"

#define PROGRAM_NAME "kxdpgun"
#define SPACE        "  "

enum {
	KXDPGUN_WAIT,
	KXDPGUN_START,
	KXDPGUN_STOP,
};

volatile int xdp_trigger = KXDPGUN_WAIT;

volatile unsigned stats_trigger = 0;

unsigned global_cpu_aff_start = 0;
unsigned global_cpu_aff_step = 1;

#define REMOTE_PORT_DEFAULT       53
#define REMOTE_PORT_DOQ_DEFAULT  853
#define LOCAL_PORT_MIN          2000
#define LOCAL_PORT_MAX         65535
#define QUIC_THREAD_PORTS        100

#define RCODE_MAX (0x0F + 1)

typedef struct {
	size_t collected;
	uint64_t duration;
	uint64_t qry_sent;
	uint64_t synack_recv;
	uint64_t ans_recv;
	uint64_t finack_recv;
	uint64_t rst_recv;
	uint64_t size_recv;
	uint64_t wire_recv;
	uint64_t rcodes_recv[RCODE_MAX];
	pthread_mutex_t mutex;
} kxdpgun_stats_t;

static kxdpgun_stats_t global_stats = { 0 };

typedef enum {
	KXDPGUN_IGNORE_NONE     = 0,
	KXDPGUN_IGNORE_QUERY    = (1 << 0),
	KXDPGUN_IGNORE_LASTBYTE = (1 << 1),
	KXDPGUN_IGNORE_CLOSE    = (1 << 2),
} xdp_gun_ignore_t;

typedef struct {
	char		dev[IFNAMSIZ];
	uint64_t	qps, duration;
	unsigned	at_once;
	uint16_t	msgid;
	uint16_t	edns_size;
	uint8_t		local_mac[6], target_mac[6];
	struct sockaddr_in6 local_ip;
	struct sockaddr_in6 target_ip;
	uint8_t		local_ip_range;
	bool		ipv6;
	bool		tcp;
	bool		quic;
	bool		quic_full_handshake;
	const char	*sending_mode;
	xdp_gun_ignore_t  ignore1;
	knot_tcp_ignore_t ignore2;
	uint16_t	target_port;
	knot_xdp_filter_flag_t flags;
	unsigned	n_threads, thread_id;
	knot_eth_rss_conf_t *rss_conf;
} xdp_gun_ctx_t;

const static xdp_gun_ctx_t ctx_defaults = {
	.dev[0] = '\0',
	.edns_size = 1232,
	.qps = 1000,
	.duration = 5000000UL, // usecs
	.at_once = 10,
	.sending_mode = "",
	.target_port = 0,
	.flags = KNOT_XDP_FILTER_UDP | KNOT_XDP_FILTER_PASS,
};

static void sigterm_handler(int signo)
{
	assert(signo == SIGTERM || signo == SIGINT);
	xdp_trigger = KXDPGUN_STOP;
}

static void sigusr_handler(int signo)
{
	assert(signo == SIGUSR1);
	if (global_stats.collected == 0) {
		stats_trigger++;
	}
}

static void clear_stats(kxdpgun_stats_t *st)
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
	memset(st->rcodes_recv, 0, sizeof(st->rcodes_recv));
	pthread_mutex_unlock(&st->mutex);
}

static size_t collect_stats(kxdpgun_stats_t *into, const kxdpgun_stats_t *what)
{
	pthread_mutex_lock(&into->mutex);
	into->duration = MAX(into->duration, what->duration);
	into->qry_sent    += what->qry_sent;
	into->synack_recv += what->synack_recv;
	into->ans_recv    += what->ans_recv;
	into->finack_recv += what->finack_recv;
	into->rst_recv    += what->rst_recv;
	into->size_recv   += what->size_recv;
	into->wire_recv   += what->wire_recv;
	for (int i = 0; i < RCODE_MAX; i++) {
		into->rcodes_recv[i] += what->rcodes_recv[i];
	}
	size_t res = ++into->collected;
	pthread_mutex_unlock(&into->mutex);
	return res;
}

static void print_stats(kxdpgun_stats_t *st, bool tcp, bool quic, bool recv)
{
	pthread_mutex_lock(&st->mutex);

#define ps(counter)  ((counter) * 1000 / (st->duration / 1000))
#define pct(counter) ((counter) * 100 / st->qry_sent)

	const char *name = tcp ? "SYNs:    " : quic ? "initials:" : "queries: ";
	printf("total %s    %"PRIu64" (%"PRIu64" pps)\n", name,
	       st->qry_sent, ps(st->qry_sent));
	if (st->qry_sent > 0 && recv) {
		if (tcp || quic) {
		name = tcp ? "established:" : "handshakes: ";
		printf("total %s %"PRIu64" (%"PRIu64" pps) (%"PRIu64"%%)\n", name,
		       st->synack_recv, ps(st->synack_recv), pct(st->synack_recv));
		}
		printf("total replies:     %"PRIu64" (%"PRIu64" pps) (%"PRIu64"%%)\n",
		       st->ans_recv, ps(st->ans_recv), pct(st->ans_recv));
		if (tcp) {
		printf("total closed:      %"PRIu64" (%"PRIu64" pps) (%"PRIu64"%%)\n",
		       st->finack_recv, ps(st->finack_recv), pct(st->finack_recv));
		printf("total reset:       %"PRIu64" (%"PRIu64" pps) (%"PRIu64"%%)\n",
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

inline static void timer_start(struct timespec *timesp)
{
	clock_gettime(CLOCK_MONOTONIC, timesp);
}

inline static uint64_t timer_end(struct timespec *timesp)
{
	struct timespec end;
	clock_gettime(CLOCK_MONOTONIC, &end);
	uint64_t res = (end.tv_sec - timesp->tv_sec) * (uint64_t)1000000;
	res += ((int64_t)end.tv_nsec - timesp->tv_nsec) / 1000;
	return res;
}

static unsigned addr_bits(bool ipv6)
{
	return ipv6 ? 128 : 32;
}

static void shuffle_sockaddr4(struct sockaddr_in *dst, struct sockaddr_in *src, uint64_t increment)
{
	memcpy(&dst->sin_addr, &src->sin_addr, sizeof(dst->sin_addr));
	if (increment > 0) {
		dst->sin_addr.s_addr = htobe32(be32toh(src->sin_addr.s_addr) + increment);
	}
}

static void shuffle_sockaddr6(struct sockaddr_in6 *dst, struct sockaddr_in6 *src, uint64_t increment)
{
	memcpy(&dst->sin6_addr, &src->sin6_addr, sizeof(dst->sin6_addr));
	if (increment > 0) {
		uint64_t *dst_addr = (uint64_t *)&dst->sin6_addr;
		uint64_t *src_addr = (uint64_t *)&src->sin6_addr;
		dst_addr[1] = htobe64(be64toh(src_addr[1]) + increment);
	}
}

static void shuffle_sockaddr(struct sockaddr_in6 *dst, struct sockaddr_in6 *src,
                             uint16_t port, uint64_t increment)
{
	dst->sin6_family = src->sin6_family;
	dst->sin6_port = htobe16(port);
	if (src->sin6_family == AF_INET6) {
		shuffle_sockaddr6(dst, src, increment);
	} else {
		shuffle_sockaddr4((struct sockaddr_in *)dst, (struct sockaddr_in *)src, increment);
	}
}

static void next_payload(struct pkt_payload **payload, int increment)
{
	if (*payload == NULL) {
		*payload = global_payloads;
	}
	for (int i = 0; i < increment; i++) {
		if ((*payload)->next == NULL) {
			*payload = global_payloads;
		} else {
			*payload = (*payload)->next;
		}
	}
}

static void put_dns_payload(struct iovec *put_into, bool zero_copy, xdp_gun_ctx_t *ctx, struct pkt_payload **payl)
{
	if (zero_copy) {
		put_into->iov_base = (*payl)->payload;
	} else {
		memcpy(put_into->iov_base, (*payl)->payload, (*payl)->len);
	}
	put_into->iov_len = (*payl)->len;
	next_payload(payl, ctx->n_threads);
}

#ifdef ENABLE_QUIC
static uint16_t get_rss_id(xdp_gun_ctx_t *ctx, uint16_t local_port)
{
	assert(ctx->rss_conf);

	const uint8_t *key = (const uint8_t *)&(ctx->rss_conf->data[ctx->rss_conf->table_size]);
	const size_t key_len = ctx->rss_conf->key_size;
	uint8_t data[2 * sizeof(struct in6_addr) + 2 * sizeof(uint16_t)];

	size_t addr_len;
	if (ctx->ipv6) {
		addr_len = sizeof(struct in6_addr);
		struct sockaddr_in6 *src = (struct sockaddr_in6 *)(&ctx->target_ip);
		struct sockaddr_in6 *dst = (struct sockaddr_in6 *)(&ctx->local_ip);
		memcpy(data, &src->sin6_addr, addr_len);
		memcpy(data + addr_len, &dst->sin6_addr, addr_len);
	} else {
		addr_len = sizeof(struct in_addr);
		struct sockaddr_in *src = (struct sockaddr_in *)(&ctx->target_ip);
		struct sockaddr_in *dst = (struct sockaddr_in *)(&ctx->local_ip);
		memcpy(data, &src->sin_addr, addr_len);
		memcpy(data + addr_len, &dst->sin_addr, addr_len);
	}

	uint16_t src_port = htobe16(ctx->target_port);
	memcpy(data + 2 * addr_len, &src_port, sizeof(src_port));
	uint16_t dst_port = htobe16(local_port);
	memcpy(data + 2 * addr_len + sizeof(uint16_t), &dst_port, sizeof(dst_port));

	size_t data_len = 2 * addr_len + 2 * sizeof(uint16_t);
	uint16_t hash = toeplitz_hash(key, key_len, data, data_len);

	return ctx->rss_conf->data[hash & ctx->rss_conf->mask];
}

static uint16_t adjust_port(xdp_gun_ctx_t *ctx, uint16_t local_port)
{
	assert(UINT16_MAX == LOCAL_PORT_MAX);

	if (local_port < LOCAL_PORT_MIN) {
		local_port = LOCAL_PORT_MIN;
	}

	if (ctx->rss_conf == NULL) {
		return local_port;
	}

	for (int i = 0; i < UINT16_MAX; i++) {
		if (ctx->thread_id == get_rss_id(ctx, local_port)) {
			break;
		}
		local_port++;
		if (local_port < LOCAL_PORT_MIN) {
			local_port = LOCAL_PORT_MIN;
		}
	}

	return local_port;
}
#endif // ENABLE_QUIC

static int alloc_pkts(knot_xdp_msg_t *pkts, struct knot_xdp_socket *xsk,
                      xdp_gun_ctx_t *ctx, uint64_t tick)
{
	uint64_t unique = (tick * ctx->n_threads + ctx->thread_id) * ctx->at_once;

	knot_xdp_msg_flag_t flags = ctx->ipv6 ? KNOT_XDP_MSG_IPV6 : 0;
	if (ctx->tcp) {
		flags |= (KNOT_XDP_MSG_TCP | KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_MSS);
	} else if (ctx->quic) {
		return ctx->at_once; // NOOP
	}

	for (int i = 0; i < ctx->at_once; i++) {
		int ret = knot_xdp_send_alloc(xsk, flags, &pkts[i]);
		if (ret != KNOT_EOK) {
			return i;
		}

		uint16_t port_range = LOCAL_PORT_MAX - LOCAL_PORT_MIN + 1;
		uint16_t local_port = LOCAL_PORT_MIN + unique % port_range;
		uint64_t ip_incr = (unique / port_range) % (1 << (addr_bits(ctx->ipv6) - ctx->local_ip_range));
		shuffle_sockaddr(&pkts[i].ip_from, &ctx->local_ip,  local_port, ip_incr);
		shuffle_sockaddr(&pkts[i].ip_to,   &ctx->target_ip, ctx->target_port, 0);

		memcpy(pkts[i].eth_from, ctx->local_mac, 6);
		memcpy(pkts[i].eth_to, ctx->target_mac, 6);

		unique++;
	}
	return ctx->at_once;
}

inline static bool check_dns_payload(struct iovec *payl, xdp_gun_ctx_t *ctx,
                                     kxdpgun_stats_t *st)
{
	if (payl->iov_len < KNOT_WIRE_HEADER_SIZE ||
	    memcmp(payl->iov_base, &ctx->msgid, sizeof(ctx->msgid)) != 0) {
		return false;
	}
	st->rcodes_recv[((uint8_t *)payl->iov_base)[3] & 0x0F]++;
	st->size_recv += payl->iov_len;
	st->ans_recv++;
	return true;
}

void *xdp_gun_thread(void *_ctx)
{
	xdp_gun_ctx_t *ctx = _ctx;
	struct knot_xdp_socket *xsk;
	struct timespec timer;
	knot_xdp_msg_t pkts[ctx->at_once];
	uint64_t errors = 0, lost = 0, duration = 0;
	kxdpgun_stats_t local_stats = { 0 };
	unsigned stats_triggered = 0;
	knot_tcp_table_t *tcp_table = NULL;
#ifdef ENABLE_QUIC
	knot_xquic_table_t *quic_table = NULL;
	struct knot_quic_creds *quic_creds = NULL;
	knot_xdp_msg_t quic_fake_req = { 0 };
	list_t quic_sessions;
	init_list(&quic_sessions);
#endif // ENABLE_QUIC

	if (ctx->tcp) {
		tcp_table = knot_tcp_table_new(ctx->qps, NULL);
		if (tcp_table == NULL) {
			ERR2("failed to allocate TCP connection table");
			return NULL;
		}
	}
	if (ctx->quic) {
#ifdef ENABLE_QUIC
		quic_creds = knot_xquic_init_creds(false, NULL, NULL);
		if (quic_creds == NULL) {
			ERR2("failed to initialize QUIC context");
			return NULL;
		}
		quic_table = knot_xquic_table_new(ctx->qps * 100, SIZE_MAX, SIZE_MAX, 1232, quic_creds);
		if (quic_table == NULL) {
			ERR2("failed to allocate QUIC connection table");
			return NULL;
		}
		ctx->target_ip.sin6_port = htobe16(ctx->target_port);

		memcpy(quic_fake_req.eth_from, ctx->target_mac,  sizeof(ctx->target_mac));
		memcpy(quic_fake_req.eth_to,   ctx->local_mac,   sizeof(ctx->local_mac));
		memcpy(&quic_fake_req.ip_from, &ctx->target_ip,  sizeof(quic_fake_req.ip_from));
		memcpy(&quic_fake_req.ip_to,   &ctx->local_ip,   sizeof(quic_fake_req.ip_to));
		quic_fake_req.flags = ctx->ipv6 ? KNOT_XDP_MSG_IPV6 : 0;
#else
		assert(0);
#endif // ENABLE_QUIC
	}

	knot_xdp_load_bpf_t mode = (ctx->thread_id == 0 ?
	                            KNOT_XDP_LOAD_BPF_ALWAYS : KNOT_XDP_LOAD_BPF_NEVER);
	/*
	 * This mutex prevents libbpf from logging:
	 * 'libbpf: can't get link by id (5535): Resource temporarily unavailable'
	*/
	pthread_mutex_lock(&global_stats.mutex);
	int ret = knot_xdp_init(&xsk, ctx->dev, ctx->thread_id, ctx->flags,
	                        LOCAL_PORT_MIN, LOCAL_PORT_MIN, mode, NULL);
	pthread_mutex_unlock(&global_stats.mutex);
	if (ret != KNOT_EOK) {
		ERR2("failed to initialize XDP socket#%u (%s)",
		     ctx->thread_id, knot_strerror(ret));
		knot_tcp_table_free(tcp_table);
		return NULL;
	}

	struct pollfd pfd = { knot_xdp_socket_fd(xsk), POLLIN, 0 };

	while (xdp_trigger == KXDPGUN_WAIT) {
		usleep(1000);
	}

	uint64_t tick = 0;
	struct pkt_payload *payload_ptr = NULL;
	next_payload(&payload_ptr, ctx->thread_id);

#ifdef ENABLE_QUIC
	knot_sweep_stats_t sweep_stats = { 0 };
	uint16_t local_ports[QUIC_THREAD_PORTS];
	uint16_t port = LOCAL_PORT_MIN;
	for (int i = 0; i < QUIC_THREAD_PORTS; ++i) {
		local_ports[i] = adjust_port(ctx, port);
		port = local_ports[i] + 1;
		assert(port >= LOCAL_PORT_MIN);
	}
	size_t local_ports_it = 0;
#endif // ENABLE_QUIC

	timer_start(&timer);

	while (duration < ctx->duration + 4000000) {

		// sending part
		if (duration < ctx->duration) {
			while (1) {
				knot_xdp_send_prepare(xsk);
				int alloced = alloc_pkts(pkts, xsk, ctx, tick);
				if (alloced < ctx->at_once) {
					lost++;
					if (alloced == 0) {
						break;
					}
				}

				if (ctx->tcp) {
					for (int i = 0; i < alloced; i++) {
						pkts[i].payload.iov_len = 0;
					}
				} else if (ctx->quic) {
#ifdef ENABLE_QUIC
					uint16_t local_port = local_ports[local_ports_it++ % QUIC_THREAD_PORTS];
					for (unsigned i = 0; i < ctx->at_once; i++) {
						knot_xquic_conn_t *newconn = NULL;
						ctx->local_ip.sin6_port = htobe16(local_port);
						ret = knot_xquic_client(quic_table, &ctx->target_ip, &ctx->local_ip, &newconn);
						if (ret == KNOT_EOK) {
							struct iovec tmp = { knot_xquic_stream_add_data(newconn, 0, NULL, payload_ptr->len), 0 };
							put_dns_payload(&tmp, false, ctx, &payload_ptr);
							if (EMPTY_LIST(quic_sessions)) {
								newconn->streams_count = -1;
							} else {
								void *session = HEAD(quic_sessions);
								rem_node(session);
								(void)knot_xquic_session_load(newconn, session);
							}
							quic_fake_req.ip_to.sin6_port = htobe16(local_port);
							ret = knot_xquic_send(quic_table, newconn, xsk, &quic_fake_req, KNOT_EOK, 1, (ctx->ignore1 & KXDPGUN_IGNORE_LASTBYTE));
						}
						if (ret == KNOT_EOK) {
							local_stats.qry_sent++;
						}
					}
					(void)knot_xdp_send_finish(xsk);
#endif // ENABLE_QUIC
					break;
				} else {
					for (int i = 0; i < alloced; i++) {
						put_dns_payload(&pkts[i].payload, false,
						                ctx, &payload_ptr);
					}
				}

				uint32_t really_sent = 0;
				(void)knot_xdp_send(xsk, pkts, alloced, &really_sent);
				assert(really_sent == alloced);
				local_stats.qry_sent += really_sent;
				(void)knot_xdp_send_finish(xsk);

				break;
			}
		}

		// receiving part
		if (!(ctx->flags & KNOT_XDP_FILTER_DROP)) {
			while (1) {
				ret = poll(&pfd, 1, 0);
				if (ret < 0) {
					errors++;
					break;
				}
				if (!pfd.revents) {
					break;
				}

				uint32_t recvd = 0;
				size_t wire = 0;
				(void)knot_xdp_recv(xsk, pkts, ctx->at_once, &recvd, &wire);
				if (recvd == 0) {
					break;
				}
				if (ctx->tcp) {
					knot_tcp_relay_t relays[recvd];
					ret = knot_tcp_recv(relays, pkts, recvd, tcp_table, NULL, ctx->ignore2);
					if (ret != KNOT_EOK) {
						errors++;
						break;
					}

					for (size_t i = 0; i < recvd; i++) {
						knot_tcp_relay_t *rl = &relays[i];
						struct iovec payl;
						switch (rl->action) {
						case XDP_TCP_ESTABLISH:
							local_stats.synack_recv++;
							if (ctx->ignore1 & KXDPGUN_IGNORE_QUERY) {
								break;
							}
							put_dns_payload(&payl, true, ctx, &payload_ptr);
							ret = knot_tcp_reply_data(rl, tcp_table,
							                          (ctx->ignore1 & KXDPGUN_IGNORE_LASTBYTE),
							                          payl.iov_base, payl.iov_len);
							if (ret != KNOT_EOK) {
								errors++;
							}
							break;
						case XDP_TCP_CLOSE:
							local_stats.finack_recv++;
							break;
						case XDP_TCP_RESET:
							local_stats.rst_recv++;
							break;
						default:
							break;
						}
						for (size_t j = 0; j < rl->inbufs_count; j++) {
							if (check_dns_payload(&rl->inbufs[j], ctx, &local_stats)) {
								if (!(ctx->ignore1 & KXDPGUN_IGNORE_CLOSE)) {
									rl->answer = XDP_TCP_CLOSE;
								}
							}
						}
					}

					ret = knot_tcp_send(xsk, relays, recvd, ctx->at_once);
					if (ret != KNOT_EOK) {
						errors++;
					}
					(void)knot_xdp_send_finish(xsk);

					knot_tcp_cleanup(tcp_table, relays, recvd);
				} else if (ctx->quic) {
#ifdef ENABLE_QUIC
					knot_xquic_conn_t *relays[recvd];
					for (size_t i = 0; i < recvd; i++) {
						ret = knot_xquic_handle(quic_table, &pkts[i], 5000000000L, &relays[i]);
						if (ret < 0 || ret > 0) {
							errors++;
							break;
						}

						knot_xquic_conn_t *rl = relays[i];
						if (rl == NULL) {
							continue;
						}

						bool sess_ticket = (gnutls_session_get_flags(rl->tls_session) & GNUTLS_SFLAGS_SESSION_TICKET);

						if (sess_ticket && !rl->session_taken && !ctx->quic_full_handshake) {
							rl->session_taken = true;
							void *session = knot_xquic_session_save(rl);
							if (session != NULL) {
								add_tail(&quic_sessions, session);
							}
						}

						if (rl->handshake_done && rl->streams_count == -1) {
							rl->streams_count = 1;

							local_stats.synack_recv++;
							if ((ctx->ignore1 & KXDPGUN_IGNORE_QUERY)) {
								knot_xquic_table_rem(relays[i], quic_table);
								relays[i] = NULL;
								continue;
							}
						}
						if (!rl->handshake_done && rl->streams_count == -1) {
							continue;
						}

						knot_xquic_stream_t *stream0 = knot_xquic_conn_get_stream(rl, 0, false);
						assert(stream0 != NULL);

						if ((ctx->ignore2 & XDP_TCP_IGNORE_ESTABLISH)) {
							knot_xquic_table_rem(relays[i], quic_table);
							relays[i] = NULL;
							local_stats.synack_recv++;
							continue;
						}

						stream0 = knot_xquic_conn_get_stream(rl, 0, false);
						if (stream0 != NULL && stream0->inbuf.iov_len > 0) {
							check_dns_payload(&stream0->inbuf, ctx, &local_stats);

							if ((ctx->ignore2 & XDP_TCP_IGNORE_DATA_ACK)) {
								knot_xquic_table_rem(relays[i], quic_table);
								relays[i] = NULL;
								continue;
							}

							stream0->inbuf.iov_len = 0;
						}
						ret = knot_xquic_send(quic_table, rl, xsk, &pkts[i], KNOT_EOK, 4, (ctx->ignore1 & KXDPGUN_IGNORE_LASTBYTE));
						if (ret != KNOT_EOK) {
							errors++;
						}
					}
					(void)knot_xdp_send_finish(xsk);
#endif // ENABLE_QUIC
				} else {
					for (int i = 0; i < recvd; i++) {
						(void)check_dns_payload(&pkts[i].payload, ctx,
						                        &local_stats);
					}
				}
				local_stats.wire_recv += wire;
				knot_xdp_recv_finish(xsk, pkts, recvd);
				pfd.revents = 0;
			}
		}

#ifdef ENABLE_QUIC
		if (ctx->quic) {
			(void)knot_xquic_table_sweep(quic_table, &sweep_stats);
		}
#endif // ENABLE_QUIC

		// speed and signal part
		uint64_t dura_exp = (local_stats.qry_sent * 1000000) / ctx->qps;
		duration = timer_end(&timer);
		if (xdp_trigger == KXDPGUN_STOP && ctx->duration > duration) {
			ctx->duration = duration;
		}
		if (stats_trigger > stats_triggered) {
			assert(stats_trigger == stats_triggered + 1);
			stats_triggered++;

			local_stats.duration = duration;
			size_t collected = collect_stats(&global_stats, &local_stats);
			assert(collected <= ctx->n_threads);
			if (collected == ctx->n_threads) {
				print_stats(&global_stats, ctx->tcp, ctx->quic,
				            !(ctx->flags & KNOT_XDP_FILTER_DROP));
				clear_stats(&global_stats);
			}
		}
		if (dura_exp > duration) {
			usleep(dura_exp - duration);
		}
		if (duration > ctx->duration) {
			usleep(1000);
		}
		tick++;
	}

	knot_xdp_deinit(xsk);

	knot_tcp_table_free(tcp_table);
#ifdef ENABLE_QUIC
	knot_xquic_table_free(quic_table);
	struct knot_quic_session *n, *nxt;
	WALK_LIST_DELSAFE(n, nxt, quic_sessions) {
		knot_xquic_session_load(NULL, n);
	}
	knot_xquic_free_creds(quic_creds);
#endif // ENABLE_QUIC

	char recv_str[40] = "", lost_str[40] = "", err_str[40] = "";
	if (!(ctx->flags & KNOT_XDP_FILTER_DROP)) {
		(void)snprintf(recv_str, sizeof(recv_str), ", received %"PRIu64, local_stats.ans_recv);
	}
	if (lost > 0) {
		(void)snprintf(lost_str, sizeof(lost_str), ", lost %"PRIu64, lost);
	}
	if (errors > 0) {
		(void)snprintf(err_str, sizeof(err_str), ", errors %"PRIu64, errors);
	}
	INFO2("thread#%02u: sent %"PRIu64"%s%s%s",
	      ctx->thread_id, local_stats.qry_sent, recv_str, lost_str, err_str);
	local_stats.duration = ctx->duration;
	collect_stats(&global_stats, &local_stats);

	return NULL;
}

static int dev2mac(const char *dev, uint8_t *mac)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return -errno;
	}
	strlcpy(ifr.ifr_name, dev, IFNAMSIZ);

	int ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
	if (ret >= 0) {
		memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	} else {
		ret = -errno;
	}
	close(fd);
	return ret;
}

static bool mac_empty(const uint8_t *mac)
{
	static const uint8_t unset_mac[6] = { 0 };
	return (memcmp(mac, unset_mac, sizeof(unset_mac)) == 0);
}

static int mac_sscan(const char *src, uint8_t *dst)
{
	int tmp[6];
	if (6 != sscanf(src, "%2x:%2x:%2x:%2x:%2x:%2x",
	                &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5])) {
		return KNOT_EINVAL;
	}

	for (int i = 0; i < 6; i++) {
		dst[i] = (uint8_t)tmp[i];
	}

	return KNOT_EOK;
}

static bool configure_target(char *target_str, char *local_ip, xdp_gun_ctx_t *ctx)
{
	int val;
	char *at = strrchr(target_str, '@');
	if (at != NULL && (val = atoi(at + 1)) > 0 && val <= 0xffff) {
		ctx->target_port = val;
		*at = '\0';
	}

	ctx->ipv6 = false;
	if (!inet_aton(target_str, &((struct sockaddr_in *)&ctx->target_ip)->sin_addr)) {
		ctx->ipv6 = true;
		ctx->target_ip.sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, target_str, &((struct sockaddr_in6 *)&ctx->target_ip)->sin6_addr) <= 0) {
			ERR2("invalid target IP");
			return false;
		}
	} else {
		ctx->target_ip.sin6_family = AF_INET;
	}

	struct sockaddr_storage via = { 0 };
	if (local_ip == NULL || ctx->dev[0] == '\0' || mac_empty(ctx->target_mac)) {
		char auto_dev[IFNAMSIZ];
		int ret = ip_route_get((struct sockaddr_storage *)&ctx->target_ip,
		                       &via,
		                       (struct sockaddr_storage *)&ctx->local_ip,
		                       (ctx->dev[0] == '\0') ? ctx->dev : auto_dev);
		if (ret < 0) {
			ERR2("can't find route to '%s' (%s)", target_str, strerror(-ret));
			return false;
		}
	}

	ctx->local_ip_range = addr_bits(ctx->ipv6); // by default use one IP
	if (local_ip != NULL) {
		at = strrchr(local_ip, '/');
		if (at != NULL && (val = atoi(at + 1)) > 0 && val <= ctx->local_ip_range) {
			ctx->local_ip_range = val;
			*at = '\0';
		}
		if (ctx->ipv6) {
			if (ctx->local_ip_range < 64 ||
			    inet_pton(AF_INET6, local_ip, &ctx->local_ip.sin6_addr) <= 0) {
				ERR2("invalid local IPv6 or unsupported prefix length");
				return false;
			}
		} else {
			if (inet_pton(AF_INET, local_ip, &ctx->local_ip.sin6_addr) <= 0) {
				ERR2("invalid local IPv4");
				return false;
			}
		}
	}

	if (mac_empty(ctx->target_mac)) {
		const struct sockaddr_storage *neigh = (via.ss_family == AF_UNSPEC) ?
		                                       (const struct sockaddr_storage *)&ctx->target_ip :
		                                       &via;
		int ret = ip_neigh_get(neigh, true, ctx->target_mac);
		if (ret < 0) {
			char neigh_str[256] = { 0 };
			(void)sockaddr_tostr(neigh_str, sizeof(neigh_str), (struct sockaddr_storage *)neigh);
			ERR2("failed to get remote MAC of target/gateway '%s' (%s)",
			     neigh_str, strerror(-ret));
			return false;
		}
	}

	if (mac_empty(ctx->local_mac)) {
		int ret = dev2mac(ctx->dev, ctx->local_mac);
		if (ret < 0) {
			ERR2("failed to get MAC of device '%s' (%s)", ctx->dev, strerror(-ret));
			return false;
		}
	}

	int ret = knot_eth_queues(ctx->dev);
	if (ret >= 0) {
		ctx->n_threads = ret;
	} else {
		ERR2("unable to get number of queues for '%s' (%s)", ctx->dev,
		     knot_strerror(ret));
		return false;
	}

	if (ctx->n_threads > 1 && ctx->quic) {
		ret = knot_eth_rss(ctx->dev, &ctx->rss_conf);
		if (ret != 0) {
			WARN2("unable to read NIC RSS configuration for '%s' (%s)",
			      ctx->dev, knot_strerror(ret));
		}
	}

	return true;
}

static void print_help(void)
{
	printf("Usage: %s [parameters] -i <queries_file> <dest_ip>\n"
	       "\n"
	       "Parameters:\n"
	       " -t, --duration <sec>     "SPACE"Duration of traffic generation.\n"
	       "                          "SPACE" (default is %"PRIu64" seconds)\n"
	       " -T, --tcp[=debug_mode]   "SPACE"Send queries over TCP.\n"
	       " -U, --quic[=debug_mode]  "SPACE"Send queries over QUIC.\n"
	       " -Q, --qps <qps>          "SPACE"Number of queries-per-second (approximately) to be sent.\n"
	       "                          "SPACE" (default is %"PRIu64" qps)\n"
	       " -b, --batch <size>       "SPACE"Send queries in a batch of defined size.\n"
	       "                          "SPACE" (default is %d for UDP, %d for TCP)\n"
	       " -r, --drop               "SPACE"Drop incoming responses (disables response statistics).\n"
	       " -p, --port <port>        "SPACE"Remote destination port.\n"
	       "                          "SPACE" (default is %d for UDP/TCP, %u for QUIC)\n"
	       " -F, --affinity <spec>    "SPACE"CPU affinity in the format [<cpu_start>][s<cpu_step>].\n"
	       "                          "SPACE" (default is %s)\n"
	       " -i, --infile <file>      "SPACE"Path to a file with query templates.\n"
	       " -I, --interface <ifname> "SPACE"Override auto-detected interface for outgoing communication.\n"
	       " -l, --local <ip[/prefix]>"SPACE"Override auto-detected source IP address or subnet.\n"
	       " -L, --local-mac <MAC>    "SPACE"Override auto-detected local MAC address.\n"
	       " -R, --remote-mac <MAC>   "SPACE"Override auto-detected remote MAC address.\n"
	       " -h, --help               "SPACE"Print the program help.\n"
	       " -V, --version            "SPACE"Print the program version.\n"
	       "\n"
	       "Arguments:\n"
	       " <dest_ip>                "SPACE"IPv4 or IPv6 address of the remote destination.\n",
	       PROGRAM_NAME, ctx_defaults.duration / 1000000, ctx_defaults.qps,
	       ctx_defaults.at_once, 1, REMOTE_PORT_DEFAULT, REMOTE_PORT_DOQ_DEFAULT, "0s1");
}

static bool sending_mode(const char *arg, xdp_gun_ctx_t *ctx)
{
	if (arg == NULL) {
		ctx->sending_mode = "";
		return true;
	} else if (strlen(arg) != 1) {
		goto mode_invalid;
	}
	ctx->sending_mode = arg;

	switch (ctx->sending_mode[0]) {
	case '0':
		if (!ctx->quic) {
			goto mode_unavailable;
		}
		ctx->quic_full_handshake = true;
		break;
	case '1':
		ctx->ignore1 = KXDPGUN_IGNORE_QUERY;
		ctx->ignore2 = XDP_TCP_IGNORE_ESTABLISH | XDP_TCP_IGNORE_FIN;
		break;
	case '2':
		ctx->ignore1 = KXDPGUN_IGNORE_QUERY;
		break;
	case '3':
		ctx->ignore1 = KXDPGUN_IGNORE_QUERY;
		ctx->ignore2 = XDP_TCP_IGNORE_FIN;
		break;
	case '5':
		ctx->ignore1 = KXDPGUN_IGNORE_LASTBYTE;
		ctx->ignore2 = XDP_TCP_IGNORE_FIN;
		break;
	case '7':
		ctx->ignore1 = KXDPGUN_IGNORE_CLOSE;
		ctx->ignore2 = XDP_TCP_IGNORE_DATA_ACK | XDP_TCP_IGNORE_FIN;
		break;
	case '8':
		if (!ctx->tcp) {
			goto mode_unavailable;
		}
		ctx->ignore1 = KXDPGUN_IGNORE_CLOSE;
		ctx->ignore2 = XDP_TCP_IGNORE_FIN;
		break;
	case '9':
		if (!ctx->tcp) {
			goto mode_unavailable;
		}
		ctx->ignore2 = XDP_TCP_IGNORE_FIN;
		break;
	default:
		goto mode_invalid;
	}

	return true;
mode_unavailable:
	ERR2("mode '%s' not available", optarg);
	return false;
mode_invalid:
	ERR2("invalid mode '%s'", optarg);
	return false;
}

static bool get_opts(int argc, char *argv[], xdp_gun_ctx_t *ctx)
{
	struct option opts[] = {
		{ "help",       no_argument,       NULL, 'h' },
		{ "version",    no_argument,       NULL, 'V' },
		{ "duration",   required_argument, NULL, 't' },
		{ "qps",        required_argument, NULL, 'Q' },
		{ "batch",      required_argument, NULL, 'b' },
		{ "drop",       no_argument,       NULL, 'r' },
		{ "port",       required_argument, NULL, 'p' },
		{ "tcp",        optional_argument, NULL, 'T' },
		{ "quic",       optional_argument, NULL, 'U' },
		{ "affinity",   required_argument, NULL, 'F' },
		{ "interface",  required_argument, NULL, 'I' },
		{ "local",      required_argument, NULL, 'l' },
		{ "infile",     required_argument, NULL, 'i' },
		{ "local-mac",  required_argument, NULL, 'L' },
		{ "remote-mac", required_argument, NULL, 'R' },
		{ NULL }
	};

	int opt = 0, arg;
	bool default_at_once = true;
	double argf;
	char *argcp, *local_ip = NULL;
	while ((opt = getopt_long(argc, argv, "hVt:Q:b:rp:T::U::F:I:l:i:L:R:", opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		case 'V':
			print_version(PROGRAM_NAME);
			exit(EXIT_SUCCESS);
		case 't':
			assert(optarg);
			argf = atof(optarg);
			if (argf > 0) {
				ctx->duration = argf * 1000000.0;
				assert(ctx->duration >= 1000);
			} else {
				ERR2("invalid duration '%s'", optarg);
				return false;
			}
			break;
		case 'Q':
			assert(optarg);
			arg = atoi(optarg);
			if (arg > 0) {
				ctx->qps = arg;
			} else {
				ERR2("invalid QPS '%s'", optarg);
				return false;
			}
			break;
		case 'b':
			assert(optarg);
			arg = atoi(optarg);
			if (arg > 0) {
				default_at_once = false;
				ctx->at_once = arg;
			} else {
				ERR2("invalid batch size '%s'", optarg);
				return false;
			}
			break;
		case 'r':
			ctx->flags &= ~KNOT_XDP_FILTER_PASS;
			ctx->flags |= KNOT_XDP_FILTER_DROP;
			break;
		case 'p':
			assert(optarg);
			arg = atoi(optarg);
			if (arg > 0 && arg <= 0xffff) {
				ctx->target_port = arg;
			} else {
				ERR2("invalid port '%s'", optarg);
				return false;
			}
			break;
		case 'T':
			ctx->tcp = true;
			ctx->quic = false;
			ctx->flags &= ~(KNOT_XDP_FILTER_UDP | KNOT_XDP_FILTER_QUIC);
			ctx->flags |= KNOT_XDP_FILTER_TCP;
			if (default_at_once) {
				ctx->at_once = 1;
			}
			if (!sending_mode(optarg, ctx)) {
				return false;
			}
			break;
		case 'U':
#ifdef ENABLE_QUIC
			ctx->quic = true;
			ctx->tcp = false;
			ctx->flags &= ~(KNOT_XDP_FILTER_UDP | KNOT_XDP_FILTER_TCP);
			ctx->flags |= KNOT_XDP_FILTER_QUIC;
			if (ctx->target_port == 0) {
				ctx->target_port = REMOTE_PORT_DOQ_DEFAULT;
			}
			if (default_at_once) {
				ctx->at_once = 1;
			}
			if (!sending_mode(optarg, ctx)) {
				return false;
			}
#else
			ERR2("QUIC not available");
			return false;
#endif // ENABLE_QUIC
			break;
		case 'F':
			assert(optarg);
			if ((arg = atoi(optarg)) > 0) {
				global_cpu_aff_start = arg;
			}
			argcp = strchr(optarg, 's');
			if (argcp != NULL && (arg = atoi(argcp + 1)) > 0) {
				global_cpu_aff_step = arg;
			}
			break;
		case 'I':
			strlcpy(ctx->dev, optarg, IFNAMSIZ);
			break;
		case 'l':
			local_ip = optarg;
			break;
		case 'i':
			if (!load_queries(optarg, ctx->edns_size, ctx->msgid)) {
				return false;
			}
			break;
		case 'L':
			if (mac_sscan(optarg, ctx->local_mac) != KNOT_EOK) {
				ERR2("invalid local MAC address '%s'", optarg);
				return false;
			}
			break;
		case 'R':
			if (mac_sscan(optarg, ctx->target_mac) != KNOT_EOK) {
				ERR2("invalid remote MAC address '%s'", optarg);
				return false;
			}
			break;
		default:
			print_help();
			return false;
		}
	}
	if (global_payloads == NULL || argc - optind != 1) {
		print_help();
		return false;
	}

	if (ctx->target_port == 0) {
		ctx->target_port = REMOTE_PORT_DEFAULT;
	}

	if (!configure_target(argv[optind], local_ip, ctx)) {
		return false;
	}

	if (ctx->qps < ctx->n_threads) {
		WARN2("QPS increased to the number of threads/queues: %u", ctx->n_threads);
		ctx->qps = ctx->n_threads;
	}
	ctx->qps /= ctx->n_threads;

	knot_xdp_mode_t mode = knot_eth_xdp_mode(if_nametoindex(ctx->dev));

	INFO2("using interface %s, XDP threads %u, %s%s%s, %s mode",
	      ctx->dev, ctx->n_threads,
	      (ctx->tcp ? "TCP" : ctx->quic ? "QUIC" : "UDP"),
	      (ctx->sending_mode[0] != '\0' ? " mode " : ""),
	      (ctx->sending_mode[0] != '\0' ? ctx->sending_mode : ""),
	      (mode == KNOT_XDP_MODE_FULL ? "native" : "emulated"));

	return true;
}

int main(int argc, char *argv[])
{
	xdp_gun_ctx_t ctx = ctx_defaults, *thread_ctxs = NULL;
	ctx.msgid = time(NULL) % UINT16_MAX;
	pthread_t *threads = NULL;

	if (!get_opts(argc, argv, &ctx)) {
		free_global_payloads();
		return EXIT_FAILURE;
	}

	thread_ctxs = calloc(ctx.n_threads, sizeof(*thread_ctxs));
	threads = calloc(ctx.n_threads, sizeof(*threads));
	if (thread_ctxs == NULL || threads == NULL) {
		ERR2("out of memory");
		free(thread_ctxs);
		free(threads);
		free_global_payloads();
		return EXIT_FAILURE;
	}
	for (int i = 0; i < ctx.n_threads; i++) {
		thread_ctxs[i] = ctx;
		thread_ctxs[i].thread_id = i;
	}

	if (!linux_at_least(5, 11)) {
		struct rlimit min_limit = { RLIM_INFINITY, RLIM_INFINITY }, cur_limit = { 0 };
		if (getrlimit(RLIMIT_MEMLOCK, &cur_limit) != 0 ||
		    cur_limit.rlim_cur != min_limit.rlim_cur ||
		    cur_limit.rlim_max != min_limit.rlim_max) {
			int ret = setrlimit(RLIMIT_MEMLOCK, &min_limit);
			if (ret != 0) {
				WARN2("unable to increase RLIMIT_MEMLOCK: %s",
				      strerror(errno));
			}
		}
	}

	pthread_mutex_init(&global_stats.mutex, NULL);

	struct sigaction stop_action = { .sa_handler = sigterm_handler };
	struct sigaction stats_action = { .sa_handler = sigusr_handler };
	sigaction(SIGINT,  &stop_action, NULL);
	sigaction(SIGTERM, &stop_action, NULL);
	sigaction(SIGUSR1, &stats_action, NULL);

	for (size_t i = 0; i < ctx.n_threads; i++) {
		unsigned affinity = global_cpu_aff_start + i * global_cpu_aff_step;
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(affinity, &set);
		(void)pthread_create(&threads[i], NULL, xdp_gun_thread, &thread_ctxs[i]);
		int ret = pthread_setaffinity_np(threads[i], sizeof(cpu_set_t), &set);
		if (ret != 0) {
			WARN2("failed to set affinity of thread#%zu to CPU#%u", i, affinity);
		}
		usleep(20000);
	}
	usleep(1000000);

	xdp_trigger = KXDPGUN_START;
	usleep(1000000);

	for (size_t i = 0; i < ctx.n_threads; i++) {
		pthread_join(threads[i], NULL);
	}
	if (global_stats.duration > 0 && global_stats.qry_sent > 0) {
		print_stats(&global_stats, ctx.tcp, ctx.quic, !(ctx.flags & KNOT_XDP_FILTER_DROP));
	}
	pthread_mutex_destroy(&global_stats.mutex);

	free(ctx.rss_conf);
	free(thread_ctxs);
	free(threads);
	free_global_payloads();

	return EXIT_SUCCESS;
}
