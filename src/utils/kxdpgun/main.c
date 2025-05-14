/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "libknot/libknot.h"
#include "libknot/xdp.h"
#include "libknot/xdp/tcp_iobuf.h"
#ifdef ENABLE_QUIC
#include <gnutls/gnutls.h>
#include "libknot/quic/quic.h"
#endif // ENABLE_QUIC
#include "contrib/atomic.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/os.h"
#include "contrib/sockaddr.h"
#include "contrib/toeplitz.h"
#include "utils/common/msg.h"
#include "utils/common/params.h"
#include "utils/kxdpgun/ip_route.h"
#include "utils/kxdpgun/load_queries.h"
#include "utils/kxdpgun/main.h"
#include "utils/kxdpgun/stats.h"

volatile int xdp_trigger = KXDPGUN_WAIT;

knot_atomic_uint64_t stats_trigger;
knot_atomic_bool stats_switch;

unsigned global_cpu_aff_start = 0;
unsigned global_cpu_aff_step = 1;

static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
static kxdpgun_stats_t global_stats = { 0 };

const static xdp_gun_ctx_t ctx_defaults = {
	.dev[0] = '\0',
	.edns_size = 1232,
	.qps = 1000,
	.duration = 5000000UL, // usecs
	.at_once = 10,
	.sending_mode = "",
	.target_port = 0,
	.flags = KNOT_XDP_FILTER_UDP | KNOT_XDP_FILTER_PASS,
	.xdp_config = { .ring_size = 2048 },
	.jw = NULL,
	.stats_period_ns = 0,
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
		ATOMIC_ADD(stats_trigger, 1);
	}
}

static unsigned addr_bits(bool ipv6)
{
	return ipv6 ? 128 : 32;
}

static void shuffle_sockaddr4(struct sockaddr_in *dst, struct sockaddr_in *src,
                              uint64_t increment)
{
	memcpy(&dst->sin_addr, &src->sin_addr, sizeof(dst->sin_addr));
	if (increment > 0) {
		dst->sin_addr.s_addr = htobe32(be32toh(src->sin_addr.s_addr) + increment);
	}
}

static void shuffle_sockaddr6(struct sockaddr_in6 *dst, struct sockaddr_in6 *src,
                              uint64_t increment)
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
		shuffle_sockaddr4((struct sockaddr_in *)dst, (struct sockaddr_in *)src,
		                  increment);
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

static void put_dns_payload(struct iovec *put_into, bool zero_copy, xdp_gun_ctx_t *ctx,
                            struct pkt_payload **payl)
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
		memcpy(data, &ctx->target_ip.sin6_addr, addr_len);
		memcpy(data + addr_len, &ctx->local_ip.sin6_addr, addr_len);
	} else {
		addr_len = sizeof(struct in_addr);
		memcpy(data, &ctx->target_ip4.sin_addr, addr_len);
		memcpy(data + addr_len, &ctx->local_ip4.sin_addr, addr_len);
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

static unsigned alloc_pkts(knot_xdp_msg_t *pkts, struct knot_xdp_socket *xsk,
                           xdp_gun_ctx_t *ctx, uint64_t tick)
{
	uint64_t unique = (tick * ctx->n_threads + ctx->thread_id) * ctx->at_once;

	knot_xdp_msg_flag_t flags = ctx->ipv6 ? KNOT_XDP_MSG_IPV6 : 0;
	if (ctx->tcp) {
		flags |= (KNOT_XDP_MSG_TCP | KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_MSS);
	} else if (ctx->quic) {
		return ctx->at_once; // NOOP
	}
	if (ctx->vlan_tci != 0) {
		flags |= KNOT_XDP_MSG_VLAN;
	}

	for (unsigned i = 0; i < ctx->at_once; i++) {
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

		pkts[i].vlan_tci = ctx->vlan_tci;

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

#ifdef ENABLE_QUIC
static int quic_alloc_cb(knot_quic_reply_t *rpl)
{
	xdp_gun_ctx_t *ctx = rpl->in_ctx;
	knot_xdp_msg_t *msg = rpl->out_ctx;

	unsigned flags = ctx->ipv6 ? KNOT_XDP_MSG_IPV6 : 0;
	if (ctx->vlan_tci != 0) {
		flags |= KNOT_XDP_MSG_VLAN;
	}

	int ret = knot_xdp_send_alloc(rpl->sock, flags, msg);
	if (ret != KNOT_EOK) {
		return ret;
	}

	memcpy(msg->eth_from, ctx->local_mac,  sizeof(ctx->local_mac));
	memcpy(msg->eth_to,   ctx->target_mac, sizeof(ctx->target_mac));
	memcpy(&msg->ip_from, &ctx->local_ip,  sizeof(msg->ip_from));
	memcpy(&msg->ip_to,   &ctx->target_ip, sizeof(msg->ip_to));

	msg->vlan_tci = ctx->vlan_tci;

	return KNOT_EOK;
}

static int quic_reply_alloc_cb(knot_quic_reply_t *rpl)
{
	return knot_xdp_reply_alloc(rpl->sock, rpl->in_ctx, rpl->out_ctx);
}

static int quic_send_cb(knot_quic_reply_t *rpl)
{
	uint32_t sent = 0;
	return knot_xdp_send(rpl->sock, rpl->out_ctx, 1, &sent);
}

static void quic_free_cb(knot_quic_reply_t *rpl)
{
	knot_xdp_send_free(rpl->sock, rpl->out_ctx, 1);
}
#endif // ENABLE_QUIC

static uint64_t timestamp_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ((uint64_t)ts.tv_sec * 1000000000) + ts.tv_nsec;
}

static void timer_start(struct timespec *out)
{
	clock_gettime(CLOCK_MONOTONIC, out);
}

static uint64_t timer_end_ns(const struct timespec *start)
{
	struct timespec end;
	clock_gettime(CLOCK_MONOTONIC, &end);
	uint64_t res = (end.tv_sec - start->tv_sec) * (uint64_t)1000000000;
	res += end.tv_nsec - start->tv_nsec;
	return res;
}

void *xdp_gun_thread(void *_ctx)
{
	xdp_gun_ctx_t *ctx = _ctx;
	struct knot_xdp_socket *xsk = NULL;
	knot_xdp_msg_t pkts[ctx->at_once];
	uint64_t duration_us = 0;
	struct timespec timer;
	kxdpgun_stats_t local_stats = { 0 }; // cumulative stats of past periods excluding the current
	kxdpgun_stats_t periodic_stats = { 0 }; // stats for the current period (see -S option)
	unsigned stats_triggered = 0;
	knot_tcp_table_t *tcp_table = NULL;
#ifdef ENABLE_QUIC
	knot_quic_table_t *quic_table = NULL;
	struct knot_creds *quic_creds = NULL;
	list_t quic_sessions;
	init_list(&quic_sessions);
#endif // ENABLE_QUIC
	list_t reuse_conns;
	init_list(&reuse_conns);
	const uint64_t extra_wait = ctx->quic ? 4000000 : 1000000;

	if (ctx->tcp) {
		tcp_table = knot_tcp_table_new(ctx->qps, NULL);
		if (tcp_table == NULL) {
			ERR2("failed to allocate TCP connection table");
			goto cleanup;
		}
	}
	if (ctx->quic) {
#ifdef ENABLE_QUIC
		quic_creds = knot_creds_init_peer(NULL, NULL, NULL, 0);
		if (quic_creds == NULL) {
			ERR2("failed to initialize QUIC context");
			goto cleanup;
		}
		quic_table = knot_quic_table_new(ctx->qps * 100, SIZE_MAX, SIZE_MAX,
		                                 1232, quic_creds);
		if (quic_table == NULL) {
			ERR2("failed to allocate QUIC connection table");
			goto cleanup;
		}
		quic_table->qlog_dir = ctx->qlog_dir;
		quic_table->flags |= KNOT_QUIC_TABLE_CLIENT_ONLY;
#else
		assert(0);
#endif // ENABLE_QUIC
	}

	knot_xdp_load_bpf_t mode =
		(ctx->thread_id == 0 ? KNOT_XDP_LOAD_BPF_ALWAYS : KNOT_XDP_LOAD_BPF_NEVER);
	/*
	 * This mutex prevents libbpf from logging:
	 * 'libbpf: can't get link by id (5535): Resource temporarily unavailable'
	 */
	pthread_mutex_lock(&stats_lock);
	int ret = knot_xdp_init(&xsk, ctx->dev, ctx->thread_id, ctx->flags,
	                        LOCAL_PORT_MIN, LOCAL_PORT_MIN, mode, &ctx->xdp_config);
	pthread_mutex_unlock(&stats_lock);
	if (ret != KNOT_EOK) {
		ERR2("failed to initialize XDP socket#%u on interface %s (%s)",
		     ctx->thread_id, ctx->dev, knot_strerror(ret));
		goto cleanup;
	}

	if (ctx->thread_id == 0) {
		STATS_HDR(ctx);
	}

	struct pollfd pfd = { knot_xdp_socket_fd(xsk), POLLIN, 0 };

	while (xdp_trigger == KXDPGUN_WAIT) {
		usleep(1000);
	}

	uint64_t tick = 0;
	struct pkt_payload *payload_ptr = NULL;
	next_payload(&payload_ptr, ctx->thread_id);

#ifdef ENABLE_QUIC
	knot_xdp_msg_t msg_out;
	knot_quic_reply_t quic_send_reply = {
		.out_payload = &msg_out.payload,
		.in_ctx = ctx,
		.out_ctx = &msg_out,
		.sock = xsk,
		.alloc_reply = quic_alloc_cb,
		.send_reply = quic_send_cb,
		.free_reply = quic_free_cb,
	};
	knot_quic_reply_t quic_reply = {
		.out_payload = &msg_out.payload,
		.out_ctx = &msg_out,
		.sock = xsk,
		.alloc_reply = quic_reply_alloc_cb,
		.send_reply = quic_send_cb,
		.free_reply = quic_free_cb,
	};

	ctx->target_ip.sin6_port = htobe16(ctx->target_port);
	knot_sweep_stats_t sweep_stats = { 0 };

	uint16_t local_ports[QUIC_THREAD_PORTS] = { 0 };
	uint16_t port = LOCAL_PORT_MIN;
	for (int i = 0; ctx->quic && i < QUIC_THREAD_PORTS; ++i) {
		local_ports[i] = adjust_port(ctx, port);
		port = local_ports[i] + 1;
		assert(port >= LOCAL_PORT_MIN);
	}
	size_t local_ports_it = 0;
#endif // ENABLE_QUIC

	local_stats.since = periodic_stats.since = timestamp_ns();
	timer_start(&timer);
	ctx->stats_start_us = local_stats.since / 1000;

	while (duration_us < ctx->duration + extra_wait) {
		// sending part
		if (duration_us < ctx->duration) {
			while (1) {
				knot_xdp_send_prepare(xsk);
				unsigned alloced = alloc_pkts(pkts, xsk, ctx, tick);
				if (alloced < ctx->at_once) {
					periodic_stats.lost += ctx->at_once - alloced;
					if (alloced == 0) {
						break;
					}
				}

				if (ctx->tcp) {
					for (uint32_t i = 0; i < alloced; i++) {
						pkts[i].payload.iov_len = 0;

						if (!EMPTY_LIST(reuse_conns)) {
							ptrnode_t *n = HEAD(reuse_conns);
							knot_tcp_relay_t *rl = n->d;
							rem_node(&n->n);
							free(n);
							struct iovec payl;
							put_dns_payload(&payl, true, ctx, &payload_ptr);
							ret = knot_tcp_reply_data(rl, tcp_table,
							                          (ctx->ignore1 & KXDPGUN_IGNORE_LASTBYTE),
							                          payl.iov_base, payl.iov_len);
							if (ret == KNOT_EOK) {
								ret = knot_tcp_send(xsk, rl, 1, ctx->at_once);
							}
							if (ret == KNOT_EOK) {
								pkts[i].flags &= ~KNOT_XDP_MSG_SYN; // skip sending respective packet
								periodic_stats.qry_sent++;
							}
							free(rl);
						}
					}
				} else if (ctx->quic) {
#ifdef ENABLE_QUIC
					uint16_t local_port = local_ports[local_ports_it++ % QUIC_THREAD_PORTS];
					ctx->local_ip.sin6_port = htobe16(local_port);

					for (unsigned i = 0; i < ctx->at_once; i++) {
						knot_quic_conn_t *newconn = NULL;
						if (!EMPTY_LIST(reuse_conns)) {
							ptrnode_t *n = HEAD(reuse_conns);
							newconn = n->d;
							rem_node(&n->n);
							assert(HEAD(reuse_conns) != n);
							free(n);
							if (newconn->streams_count < 1) {
								newconn = NULL; // un-re-usable conn
							} else {
								ctx->local_ip.sin6_port = knot_quic_conn_local_port(newconn);
								ret = KNOT_EOK;
							}
						}
						if (newconn == NULL) {
							ret = knot_quic_client(quic_table, &ctx->target_ip, &ctx->local_ip,
							                       NULL, &newconn);
						}
						if (ret == KNOT_EOK) {
							struct iovec tmp = {
								knot_quic_stream_add_data(newconn, (newconn->streams_first + newconn->streams_count) * 4,
								                          NULL, payload_ptr->len),
								0
							};
							put_dns_payload(&tmp, false, ctx, &payload_ptr);
							if (newconn->streams_count < 2) {
								if (EMPTY_LIST(quic_sessions)) {
									newconn->streams_count = -1;
								} else {
									void *session = HEAD(quic_sessions);
									rem_node(session);
									(void)knot_quic_session_load(newconn, session);
								}
							}
							ret = knot_quic_send(quic_table, newconn, &quic_send_reply, 1,
							                     (ctx->ignore1 & KXDPGUN_IGNORE_LASTBYTE) ? KNOT_QUIC_SEND_IGNORE_LASTBYTE : 0);
						}
						if (ret == KNOT_EOK) {
							periodic_stats.qry_sent++;
						}
					}
					(void)knot_xdp_send_finish(xsk);
#endif // ENABLE_QUIC
					break;
				} else {
					for (uint32_t i = 0; i < alloced; i++) {
						put_dns_payload(&pkts[i].payload, false,
						                ctx, &payload_ptr);
					}
				}

				uint32_t really_sent = 0;
				if (knot_xdp_send(xsk, pkts, alloced, &really_sent) != KNOT_EOK) {
					periodic_stats.lost += alloced;
				}
				periodic_stats.qry_sent += really_sent;
				(void)knot_xdp_send_finish(xsk);

				break;
			}
		}

		// receiving part
		if (!(ctx->flags & KNOT_XDP_FILTER_DROP)) {
			while (1) {
				ret = poll(&pfd, 1, 0);
				if (ret < 0) {
					periodic_stats.errors++;
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

					for (size_t i = 0; i < recvd; i++) {
						knot_tcp_relay_t *rl = &relays[i];
						ret = knot_tcp_recv(rl, &pkts[i], tcp_table, NULL, ctx->ignore2);
						if (ret != KNOT_EOK) {
							periodic_stats.errors++;
							continue;
						}

						struct iovec payl;
						switch (rl->action) {
						case XDP_TCP_ESTABLISH:
							periodic_stats.synack_recv++;
							if (ctx->ignore1 & KXDPGUN_IGNORE_QUERY) {
								break;
							}
							put_dns_payload(&payl, true, ctx, &payload_ptr);
							ret = knot_tcp_reply_data(rl, tcp_table,
							                          (ctx->ignore1 & KXDPGUN_IGNORE_LASTBYTE),
							                          payl.iov_base, payl.iov_len);
							if (ret != KNOT_EOK) {
								periodic_stats.errors++;
							}
							break;
						case XDP_TCP_CLOSE:
							periodic_stats.finack_recv++;
							break;
						case XDP_TCP_RESET:
							periodic_stats.rst_recv++;
							break;
						default:
							break;
						}
						for (size_t j = 0; rl->inbf != NULL && j < rl->inbf->n_inbufs; j++) {
							if (check_dns_payload(&rl->inbf->inbufs[j], ctx, &periodic_stats)) {
								if (!(ctx->ignore1 & KXDPGUN_IGNORE_CLOSE)) {
									rl->answer = XDP_TCP_CLOSE;
								} else if ((ctx->ignore1 & KXDPGUN_REUSE_CONN)) {
									knot_tcp_relay_t *rl_copy = malloc(sizeof(*rl));
									memcpy(rl_copy, rl, sizeof(*rl));
									ptrlist_add(&reuse_conns, rl_copy, NULL);
									rl_copy->answer = XDP_TCP_NOOP;
									rl_copy->auto_answer = 0;
								}
							}
						}
					}

					ret = knot_tcp_send(xsk, relays, recvd, ctx->at_once);
					if (ret != KNOT_EOK) {
						periodic_stats.errors++;
					}
					(void)knot_xdp_send_finish(xsk);

					knot_tcp_cleanup(tcp_table, relays, recvd);
				} else if (ctx->quic) {
#ifdef ENABLE_QUIC
					for (size_t i = 0; i < recvd; i++) {
						knot_xdp_msg_t *msg_in = &pkts[i];
						knot_quic_conn_t *conn;

						quic_reply.ip_rem = (struct sockaddr_storage *)&msg_in->ip_from;
						quic_reply.ip_loc = (struct sockaddr_storage *)&msg_in->ip_to;
						quic_reply.in_payload = &msg_in->payload;
						quic_reply.in_ctx = msg_in;

						ret = knot_quic_handle(quic_table, &quic_reply, 5000000000L, &conn);
						if (ret == KNOT_ECONN) {
							periodic_stats.rst_recv++;
							knot_quic_cleanup(&conn, 1);
							continue;
						} else if (ret != 0) {
							periodic_stats.errors++;
							knot_quic_cleanup(&conn, 1);
							break;
						}

						if (conn == NULL || conn->conn == NULL) {
							knot_quic_cleanup(&conn, 1);
							continue;
						}

						if (!ctx->quic_full_handshake && knot_quic_session_available(conn)) {
							void *session = knot_quic_session_save(conn);
							if (session != NULL) {
								add_tail(&quic_sessions, session);
							}
						}

						if ((conn->flags & KNOT_QUIC_CONN_HANDSHAKE_DONE) && conn->streams_count == -1) {
							conn->streams_count = 1;

							periodic_stats.synack_recv++;
							if ((ctx->ignore1 & KXDPGUN_IGNORE_QUERY)) {
								knot_quic_table_rem(conn, quic_table);
								knot_quic_cleanup(&conn, 1);
								continue;
							}
						}
						if (!(conn->flags & KNOT_QUIC_CONN_HANDSHAKE_DONE) && conn->streams_count == -1) {
							continue;
						}
						assert(conn->streams_count > 0);

						if ((ctx->ignore2 & XDP_TCP_IGNORE_ESTABLISH)) {
							knot_quic_table_rem(conn, quic_table);
							knot_quic_cleanup(&conn, 1);
							periodic_stats.synack_recv++;
							continue;
						}

						int64_t s0id;
						knot_quic_stream_t *stream0 = knot_quic_stream_get_process(conn, &s0id);
						if (stream0 != NULL && stream0->inbufs != NULL && stream0->inbufs->n_inbufs > 0) {
							check_dns_payload(&stream0->inbufs->inbufs[0], ctx, &periodic_stats);
							stream0->inbufs->n_inbufs = 0; // signal that data have been read out

							if ((ctx->ignore2 & XDP_TCP_IGNORE_DATA_ACK)) {
								knot_quic_table_rem(conn, quic_table);
								knot_quic_cleanup(&conn, 1);
								continue;
							} else if ((ctx->ignore1 & KXDPGUN_REUSE_CONN)) {
								/* keep the number of outstanding streams below MAX_STREAMS_PER_CONN,
								 * while preserving at least one at all times */
								if (conn->streams_count > 1) {
									knot_quic_conn_stream_free(conn, conn->streams_first * 4);
								}
								ptrlist_add(&reuse_conns, conn, NULL);
							}
						}
						ret = knot_quic_send(quic_table, conn, &quic_reply, 4,
						                     (ctx->ignore1 & KXDPGUN_IGNORE_LASTBYTE) ? KNOT_QUIC_SEND_IGNORE_LASTBYTE : 0);
						if (ret != KNOT_EOK) {
							periodic_stats.errors++;
						}

						if (!(ctx->ignore1 & KXDPGUN_IGNORE_CLOSE)
						    && (conn->flags & KNOT_QUIC_CONN_SESSION_TAKEN)
						    && stream0 != NULL && stream0->inbufs != NULL
						    && stream0->inbufs->n_inbufs == 0) {
							assert(!(ctx->ignore2 & XDP_TCP_IGNORE_DATA_ACK));
							quic_reply.handle_ret = KNOT_QUIC_HANDLE_RET_CLOSE;
							ret = knot_quic_send(quic_table, conn, &quic_reply, 1, 0);
							knot_quic_table_rem(conn, quic_table);
							knot_quic_cleanup(&conn, 1);
							if (ret != KNOT_EOK) {
								periodic_stats.errors++;
							}
						}
					}
					(void)knot_xdp_send_finish(xsk);
#endif // ENABLE_QUIC
				} else {
					for (uint32_t i = 0; i < recvd; i++) {
						check_dns_payload(&pkts[i].payload, ctx, &periodic_stats);
					}
				}
				periodic_stats.wire_recv += wire;
				knot_xdp_recv_finish(xsk, pkts, recvd);
				pfd.revents = 0;
			}
		}

#ifdef ENABLE_QUIC
		if (ctx->quic) {
			(void)knot_quic_table_sweep(quic_table, NULL, &sweep_stats);
		}
#endif // ENABLE_QUIC

		// speed and signal part
		uint64_t duration_ns = timer_end_ns(&timer);
		duration_us = duration_ns / 1000;
		uint64_t dura_exp = ((local_stats.qry_sent + periodic_stats.qry_sent) * 1000000) / ctx->qps;
		if (ctx->thread_id == 0 && ctx->stats_period_ns != 0 && global_stats.collected == 0
		    && (duration_ns - (periodic_stats.since - local_stats.since)) >= ctx->stats_period_ns) {
			ATOMIC_SET(stats_switch, STATS_PERIODIC);
			ATOMIC_ADD(stats_trigger, 1);
		}

		if (xdp_trigger == KXDPGUN_STOP && ctx->duration > duration_us) {
			ctx->duration = duration_us;
		}
		uint64_t tmp_stats_trigger = ATOMIC_GET(stats_trigger);
		if (duration_us < ctx->duration && tmp_stats_trigger > stats_triggered) {
			bool tmp_stats_switch = ATOMIC_GET(stats_switch);
			stats_triggered = tmp_stats_trigger;

			local_stats.until = periodic_stats.until = local_stats.since + duration_ns;
			kxdpgun_stats_t cumulative_stats = periodic_stats;
			if (tmp_stats_switch == STATS_PERIODIC) {
				collect_periodic_stats(&local_stats, &periodic_stats);
				clear_stats(&periodic_stats);
				periodic_stats.since = local_stats.since + duration_ns;
			} else {
				collect_periodic_stats(&cumulative_stats, &local_stats);
				cumulative_stats.since = local_stats.since;
			}

			pthread_mutex_lock(&stats_lock);
			size_t collected = collect_stats(&global_stats, &cumulative_stats);
			assert(collected <= ctx->n_threads);
			if (collected == ctx->n_threads) {
				STATS_FMT(ctx, &global_stats, tmp_stats_switch);
				if (!JSON_MODE(*ctx)) {
					puts(STATS_SECTION_SEP);
				}
				clear_stats(&global_stats);
				ATOMIC_SET(stats_switch, STATS_SUM);
			}
			pthread_mutex_unlock(&stats_lock);
		}
		if (dura_exp > duration_us) {
			usleep(dura_exp - duration_us);
		}
		if (duration_us > ctx->duration) {
			usleep(1000);
		}
		tick++;
	}
	periodic_stats.until = local_stats.since + timer_end_ns(&timer) - extra_wait * 1000;
	collect_periodic_stats(&local_stats, &periodic_stats);

	STATS_THRD(ctx, &local_stats);

	pthread_mutex_lock(&stats_lock);
	collect_stats(&global_stats, &local_stats);
	pthread_mutex_unlock(&stats_lock);

cleanup:
	knot_xdp_deinit(xsk);

	if (ctx->tcp) {
		ptrlist_deep_free(&reuse_conns, NULL);
	} else if (ctx->quic) {
		ptrlist_free(&reuse_conns, NULL); // stored conns get freed as part of xyz_table_free
	} else {
		assert(EMPTY_LIST(reuse_conns));
	}
	knot_tcp_table_free(tcp_table);

#ifdef ENABLE_QUIC
	knot_quic_table_free(quic_table);
	struct knot_tls_session *n, *nxt;
	WALK_LIST_DELSAFE(n, nxt, quic_sessions) {
		knot_quic_session_load(NULL, n);
	}
	knot_creds_free(quic_creds);
#endif // ENABLE_QUIC

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

static bool resolve_name(char *target_str, xdp_gun_ctx_t *ctx)
{
	struct addrinfo *res = NULL, hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = 0, // any socket type
		.ai_protocol = 0, // any protocol
	};

	int err = 0;
	if ((err = getaddrinfo(target_str, NULL, &hints, &res)) != 0) {
		ERR2("failed to resolve '%s' (%s)", target_str, gai_strerror(err));
		goto cleanup;
	}

	for (struct addrinfo *i = res; i != NULL; i = i->ai_next) {
		switch (i->ai_family) {
		case AF_INET:
		case AF_INET6:
			ctx->ipv6 = (i->ai_family == AF_INET6);
			assert(sizeof(ctx->target_ip_ss) >= i->ai_addrlen);
			memcpy(&ctx->target_ip_ss, i->ai_addr, i->ai_addrlen);
			goto cleanup;
		default:
			break;
		};
	}
	err = 1;

cleanup:
	if (res != NULL) {
		freeaddrinfo(res);
	}
	return (err == 0);
}

static bool configure_target(char *target_str, char *local_ip, xdp_gun_ctx_t *ctx)
{
	int val;
	char *at = strrchr(target_str, '@');
	if (at != NULL && (val = atoi(at + 1)) > 0 && val <= 0xffff) {
		ctx->target_port = val;
		*at = '\0';
	}

	if (!resolve_name(target_str, ctx)) {
		return false;
	}

	struct sockaddr_storage via = { 0 };
	if (local_ip == NULL || ctx->dev[0] == '\0' || mac_empty(ctx->target_mac)) {
		char auto_dev[IFNAMSIZ];
		int ret = ip_route_get(&ctx->target_ip_ss,
		                       &via,
		                       &ctx->local_ip_ss,
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
			if (inet_pton(AF_INET, local_ip, &ctx->local_ip4.sin_addr) <= 0) {
				ERR2("invalid local IPv4");
				return false;
			}
		}
	}

	if (mac_empty(ctx->target_mac)) {
		const struct sockaddr_storage *neigh = (via.ss_family == AF_UNSPEC) ?
		                                       &ctx->target_ip_ss : &via;
		int ret = ip_neigh_get(neigh, true, ctx->target_mac);
		if (ret < 0) {
			char neigh_str[256] = { 0 };
			sockaddr_tostr(neigh_str, sizeof(neigh_str), (struct sockaddr_storage *)neigh);
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
	printf("Usage: %s [options] -i <queries_file> <dest_ip>\n"
	       "\n"
	       "Options:\n"
	       " -t, --duration <sec>       "SPACE"Duration of traffic generation.\n"
	       "                            "SPACE" (default is %"PRIu64" seconds)\n"
	       " -T, --tcp[=debug_mode]     "SPACE"Send queries over TCP.\n"
	       " -U, --quic[=debug_mode]    "SPACE"Send queries over QUIC.\n"
	       " -Q, --qps <qps>            "SPACE"Number of queries-per-second (approximately) to be sent.\n"
	       "                            "SPACE" (default is %"PRIu64" qps)\n"
	       " -b, --batch <size>         "SPACE"Send queries in a batch of defined size.\n"
	       "                            "SPACE" (default is %d for UDP, %d for TCP)\n"
	       " -r, --drop                 "SPACE"Drop incoming responses (disables response statistics).\n"
	       " -p, --port <port>          "SPACE"Remote destination port.\n"
	       "                            "SPACE" (default is %d for UDP/TCP, %u for QUIC)\n"
	       " -F, --affinity <spec>      "SPACE"CPU affinity in the format [<cpu_start>][s<cpu_step>].\n"
	       "                            "SPACE" (default is %s)\n"
	       " -I, --interface <ifname>   "SPACE"Override auto-detected interface for outgoing communication.\n"
	       " -i, --infile <file>        "SPACE"Path to a file with query templates.\n"
	       " -B, --binary               "SPACE"Specify that input file is in binary format (<length:2><wire:length>).\n"
	       " -l, --local <ip[/prefix]>  "SPACE"Override auto-detected source IP address or subnet.\n"
	       " -L, --local-mac <MAC>      "SPACE"Override auto-detected local MAC address.\n"
	       " -R, --remote-mac <MAC>     "SPACE"Override auto-detected remote MAC address.\n"
	       " -v, --vlan <id>            "SPACE"Add VLAN 802.1Q header with the given id.\n"
	       " -e, --edns-size <size>     "SPACE"EDNS UDP payload size, range 512-4096 (default 1232)\n"
	       " -m, --mode <mode>          "SPACE"Set XDP mode (auto, copy, generic).\n"
	       " -G, --qlog <path>          "SPACE"Output directory for qlog (useful for QUIC only).\n"
	       " -j, --json                 "SPACE"Output statistics in json.\n"
	       " -S, --stats-period <period>"SPACE"Enable periodic statistics printout in milliseconds.\n"
	       " -h, --help                 "SPACE"Print the program help.\n"
	       " -V, --version              "SPACE"Print the program version.\n"
	       "\n"
	       "Parameters:\n"
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
		ctx->ignore1 = KXDPGUN_IGNORE_CLOSE;
		ctx->ignore2 = XDP_TCP_IGNORE_FIN;
		break;
	case '9':
		if (!ctx->tcp) {
			goto mode_unavailable;
		}
		ctx->ignore2 = XDP_TCP_IGNORE_FIN;
		break;
	case 'R':
		ctx->ignore1 = KXDPGUN_IGNORE_CLOSE | KXDPGUN_REUSE_CONN;
		ctx->quic_full_handshake = true;
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

static int set_mode(const char *arg, knot_xdp_config_t *config)
{
	assert(arg != NULL);
	assert(config != NULL);

	if (strcmp(arg, "auto") == 0) {
		config->force_copy = false;
		config->force_generic = false;
		return KNOT_EOK;
	}

	if (strcmp(arg, "copy") == 0) {
		config->force_copy = true;
		config->force_generic = false;
		return KNOT_EOK;
	}

	if (strcmp(arg, "generic") == 0) {
		config->force_copy = false;
		config->force_generic = true;
		return KNOT_EOK;
	}

	return KNOT_EINVAL;
}

static bool get_opts(int argc, char *argv[], xdp_gun_ctx_t *ctx)
{
	const char *opts_str = "hV::t:Q:b:rp:T::U::F:I:i:Bl:L:R:v:e:m:G:jS:";
	struct option opts[] = {
		{ "help",         no_argument,       NULL, 'h' },
		{ "version",      optional_argument, NULL, 'V' },
		{ "duration",     required_argument, NULL, 't' },
		{ "qps",          required_argument, NULL, 'Q' },
		{ "batch",        required_argument, NULL, 'b' },
		{ "drop",         no_argument,       NULL, 'r' },
		{ "port",         required_argument, NULL, 'p' },
		{ "tcp",          optional_argument, NULL, 'T' },
		{ "quic",         optional_argument, NULL, 'U' },
		{ "affinity",     required_argument, NULL, 'F' },
		{ "interface",    required_argument, NULL, 'I' },
		{ "infile",       required_argument, NULL, 'i' },
		{ "binary",       no_argument,       NULL, 'B' },
		{ "local",        required_argument, NULL, 'l' },
		{ "local-mac",    required_argument, NULL, 'L' },
		{ "remote-mac",   required_argument, NULL, 'R' },
		{ "vlan",         required_argument, NULL, 'v' },
		{ "edns-size",    required_argument, NULL, 'e' },
		{ "mode",         required_argument, NULL, 'm' },
		{ "qlog",         required_argument, NULL, 'G' },
		{ "json",         no_argument,       NULL, 'j' },
		{ "stats-period", required_argument, NULL, 'S' },
		{ 0 }
	};

	int opt = 0, arg;
	bool default_at_once = true;
	double argf;
	char *argcp, *local_ip = NULL;
	input_t input = { .format = TXT };
	while ((opt = getopt_long(argc, argv, opts_str, opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		case 'V':
			print_version(PROGRAM_NAME, optarg != NULL);
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
		case 'i':
			input.path = optarg;
			break;
		case 'B':
			input.format = BIN;
			break;
		case 'l':
			local_ip = optarg;
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
		case 'v':
			assert(optarg);
			arg = atoi(optarg);
			if (arg > 0 && arg < 4095) {
				uint16_t id = arg;
				ctx->vlan_tci = htobe16(id);
			} else {
				ERR2("invalid VLAN id '%s'", optarg);
				return false;
			}
			break;
		case 'e':
			assert(optarg);
			arg = atoi(optarg);
			if (arg >= 512 && arg <= 4096) {
				ctx->edns_size = arg;
			} else {
				ERR2("invalid edns size '%s'", optarg);
				return false;
			}
			break;
		case 'm':
			assert(optarg);
			if (set_mode(optarg, &ctx->xdp_config) != KNOT_EOK) {
				ERR2("invalid mode '%s'", optarg);
				return false;
			}
			break;
		case 'G':
			ctx->qlog_dir = optarg;
			break;
		case 'S':
			assert(optarg);
			arg = atoi(optarg);
			if (arg > 0) {
				ctx->stats_period_ns = arg * 1000000ull; // convert to ns
			} else {
				ERR2("period must be a positive integer\n");
				return false;
			}
			break;
		case 'j':
			if ((ctx->jw = jsonw_new(stdout, JSON_INDENT)) == NULL) {
				ERR2("failed to use JSON");
				return false;
			}
			break;
		default:
			print_help();
			return false;
		}
	}
	if (input.path == NULL) {
		print_help();
		return false;
	}
	size_t qcount = ctx->duration / 1000000 * ctx->qps;
	if (!load_queries(&input, ctx->edns_size, ctx->msgid, qcount)) {
		return false;
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

	return true;
}

int main(int argc, char *argv[])
{
	int ecode = EXIT_FAILURE;
	ATOMIC_INIT(stats_trigger, 0);
	ATOMIC_INIT(stats_switch, STATS_SUM);

	xdp_gun_ctx_t ctx = ctx_defaults, *thread_ctxs = NULL;
	ctx.msgid = time(NULL) % UINT16_MAX;
	ctx.runid = timestamp_ns() / 1000;
	ctx.argv = argv;
	pthread_t *threads = NULL;

	if (!get_opts(argc, argv, &ctx)) {
		goto err;
	}

	if (JSON_MODE(ctx)) {
		jsonw_list(ctx.jw, NULL); // wrap the json in a list, for syntactic correctness
	}

	thread_ctxs = calloc(ctx.n_threads, sizeof(*thread_ctxs));
	threads = calloc(ctx.n_threads, sizeof(*threads));
	if (thread_ctxs == NULL || threads == NULL) {
		ERR2("out of memory");
		goto err;
	}
	for (uint32_t i = 0; i < ctx.n_threads; i++) {
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
				WARN2("unable to increase RLIMIT_MEMLOCK: %s", strerror(errno));
			}
		}
	}

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
	if (DURATION_US(global_stats) > 0 && global_stats.qry_sent > 0) {
		if (!JSON_MODE(ctx)) {
			puts(STATS_SECTION_SEP);
		}
		STATS_FMT(&ctx, &global_stats, STATS_SUM);
	}
	pthread_mutex_destroy(&stats_lock);

	ecode = EXIT_SUCCESS;

err:
	ATOMIC_DEINIT(stats_trigger);
	ATOMIC_DEINIT(stats_switch);
	free(ctx.rss_conf);
	free(thread_ctxs);
	free(threads);
	free_global_payloads();
	if (JSON_MODE(ctx)) {
		jsonw_end(ctx.jw);
		jsonw_free(&ctx.jw);
	}
	return ecode;
}
