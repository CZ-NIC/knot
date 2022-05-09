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
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/os.h"
#include "contrib/sockaddr.h"
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

#define LOCAL_PORT_DEFAULT 53
#define LOCAL_PORT_MIN   2000
#define LOCAL_PORT_MAX  65535

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
	struct sockaddr_storage local_ip, target_ip;
	uint8_t		local_ip_range;
	bool		ipv6;
	bool		tcp;
	char		tcp_mode;
	xdp_gun_ignore_t  ignore1;
	knot_tcp_ignore_t ignore2;
	uint16_t	target_port;
	uint16_t	listen_port;
	knot_xdp_filter_flag_t flags;
	unsigned	n_threads, thread_id;
} xdp_gun_ctx_t;

const static xdp_gun_ctx_t ctx_defaults = {
	.dev[0] = '\0',
	.edns_size = 1232,
	.qps = 1000,
	.duration = 5000000UL, // usecs
	.at_once = 10,
	.tcp_mode = '0',
	.target_port = LOCAL_PORT_DEFAULT,
	.listen_port = LOCAL_PORT_MIN,
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

static void print_stats(kxdpgun_stats_t *st, bool tcp, bool recv)
{
	pthread_mutex_lock(&st->mutex);

#define ps(counter)  ((counter) * 1000 / (st->duration / 1000))
#define pct(counter) ((counter) * 100 / st->qry_sent)

	printf("total %s     %"PRIu64" (%"PRIu64" pps)\n",
	       tcp ? "SYN:    " : "queries:", st->qry_sent, ps(st->qry_sent));
	if (st->qry_sent > 0 && recv) {
		if (tcp) {
		printf("total established: %"PRIu64" (%"PRIu64" pps) (%"PRIu64"%%)\n",
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

static void shuffle_sockaddr4(void *dst_v, struct sockaddr_storage *src_ss, uint64_t increment)
{
	struct sockaddr_in *dst = dst_v, *src = (struct sockaddr_in *)src_ss;
	memcpy(&dst->sin_addr, &src->sin_addr, sizeof(dst->sin_addr));
	if (increment > 0) {
		dst->sin_addr.s_addr = htobe32(be32toh(src->sin_addr.s_addr) + increment);
	}
}

static void shuffle_sockaddr6(void *dst_v, struct sockaddr_storage *src_ss, uint64_t increment)
{
	struct sockaddr_in6 *dst = dst_v, *src = (struct sockaddr_in6 *)src_ss;
	memcpy(&dst->sin6_addr, &src->sin6_addr, sizeof(dst->sin6_addr));
	if (increment > 0) {
		dst->sin6_addr.__in6_u.__u6_addr32[2] =
			htobe32(be32toh(src->sin6_addr.__in6_u.__u6_addr32[2]) + (increment >> 32));
		dst->sin6_addr.__in6_u.__u6_addr32[3] =
			htobe32(be32toh(src->sin6_addr.__in6_u.__u6_addr32[3]) + (increment & 0xffffffff));
	}
}

static void shuffle_sockaddr(struct sockaddr_in6 *dst, struct sockaddr_storage *ss,
                             uint16_t port, uint64_t increment)
{
	dst->sin6_family = ss->ss_family;
	dst->sin6_port = htobe16(port);
	if (ss->ss_family == AF_INET6) {
		shuffle_sockaddr6(dst, ss, increment);
	} else {
		shuffle_sockaddr4(dst, ss, increment);
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

static int alloc_pkts(knot_xdp_msg_t *pkts, struct knot_xdp_socket *xsk,
                      xdp_gun_ctx_t *ctx, uint64_t tick)
{
	uint64_t unique = (tick * ctx->n_threads + ctx->thread_id) * ctx->at_once;

	knot_xdp_msg_flag_t flags = ctx->ipv6 ? KNOT_XDP_MSG_IPV6 : 0;
	if (ctx->tcp) {
		flags |= (KNOT_XDP_MSG_TCP | KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_MSS);
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

	if (ctx->tcp) {
		tcp_table = knot_tcp_table_new(ctx->qps, NULL);
		if (tcp_table == NULL) {
			ERR2("failed to allocate TCP connection table\n");
			return NULL;
		}
	}

	knot_xdp_load_bpf_t mode = (ctx->thread_id == 0 ?
	                            KNOT_XDP_LOAD_BPF_ALWAYS : KNOT_XDP_LOAD_BPF_NEVER);
	int ret = knot_xdp_init(&xsk, ctx->dev, ctx->thread_id, ctx->flags,
	                        ctx->listen_port, ctx->listen_port, mode);
	if (ret != KNOT_EOK) {
		ERR2("failed to initialize XDP socket#%u (%s)\n",
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

	timer_start(&timer);

	while (duration < ctx->duration + 1000000) {

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
				print_stats(&global_stats, ctx->tcp,
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
	INFO2("thread#%02u: sent %"PRIu64"%s%s%s\n",
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
		ctx->target_ip.ss_family = AF_INET6;
		if (inet_pton(AF_INET6, target_str, &((struct sockaddr_in6 *)&ctx->target_ip)->sin6_addr) <= 0) {
			ERR2("invalid target IP\n");
			return false;
		}
	} else {
		ctx->target_ip.ss_family = AF_INET;
	}

	struct sockaddr_storage via = { 0 };
	int ret = ip_route_get(&ctx->target_ip, &via, &ctx->local_ip, ctx->dev);
	if (ret < 0) {
		ERR2("can't find route to '%s' (%s)\n", target_str, strerror(-ret));
		return false;
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
			    inet_pton(AF_INET6, local_ip, &((struct sockaddr_in6 *)&ctx->local_ip)->sin6_addr) <= 0) {
				ERR2("invalid local IPv6 or unsupported prefix length\n");
				return false;
			}
		} else {
			if (inet_pton(AF_INET, local_ip, &((struct sockaddr_in *)&ctx->local_ip)->sin_addr) <= 0) {
				ERR2("invalid local IPv4\n");
				return false;
			}
		}
	}

	const struct sockaddr_storage *neigh = via.ss_family == AF_UNSPEC ? &ctx->target_ip : &via;
	ret = ip_neigh_get(neigh, true, ctx->target_mac);
	if (ret < 0) {
		char neigh_str[256] = { 0 };
		(void)sockaddr_tostr(neigh_str, sizeof(neigh_str), neigh);
		ERR2("failed to get remote MAC of target/gateway '%s' (%s)\n",
		     neigh_str, strerror(-ret));
		return false;
	}

	ret = dev2mac(ctx->dev, ctx->local_mac);
	if (ret < 0) {
		ERR2("failed to get MAC of device '%s' (%s)\n", ctx->dev, strerror(-ret));
		return false;
	}

	ret = knot_eth_queues(ctx->dev);
	if (ret >= 0) {
		ctx->n_threads = ret;
	} else {
		ERR2("unable to get number of queues for '%s' (%s)\n", ctx->dev,
		     knot_strerror(ret));
		return false;
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
	       " -Q, --qps <qps>          "SPACE"Number of queries-per-second (approximately) to be sent.\n"
	       "                          "SPACE" (default is %"PRIu64" qps)\n"
	       " -b, --batch <size>       "SPACE"Send queries in a batch of defined size.\n"
	       "                          "SPACE" (default is %d for UDP, %d for TCP)\n"
	       " -r, --drop               "SPACE"Drop incoming responses (disables response statistics).\n"
	       " -p, --port <port>        "SPACE"Remote destination port.\n"
	       "                          "SPACE" (default is %d)\n"
	       " -F, --affinity <spec>    "SPACE"CPU affinity in the format [<cpu_start>][s<cpu_step>].\n"
	       "                          "SPACE" (default is %s)\n"
	       " -i, --infile <file>      "SPACE"Path to a file with query templates.\n"
	       " -I, --interface <ifname> "SPACE"Override auto-detected interface for outgoing communication.\n"
	       " -l, --local <ip[/prefix]>"SPACE"Override auto-detected source IP address or subnet.\n"
	       " -h, --help               "SPACE"Print the program help.\n"
	       " -V, --version            "SPACE"Print the program version.\n"
	       "\n"
	       "Arguments:\n"
	       " <dest_ip>                "SPACE"IPv4 or IPv6 address of the remote destination.\n",
	       PROGRAM_NAME, ctx_defaults.duration / 1000000, ctx_defaults.qps,
	       ctx_defaults.at_once, 1, LOCAL_PORT_DEFAULT, "0s1");
}

static bool get_opts(int argc, char *argv[], xdp_gun_ctx_t *ctx)
{
	struct option opts[] = {
		{ "help",      no_argument,       NULL, 'h' },
		{ "version",   no_argument,       NULL, 'V' },
		{ "duration",  required_argument, NULL, 't' },
		{ "qps",       required_argument, NULL, 'Q' },
		{ "batch",     required_argument, NULL, 'b' },
		{ "drop",      no_argument,       NULL, 'r' },
		{ "port",      required_argument, NULL, 'p' },
		{ "tcp",       optional_argument, NULL, 'T' },
		{ "affinity",  required_argument, NULL, 'F' },
		{ "interface", required_argument, NULL, 'I' },
		{ "local",     required_argument, NULL, 'l' },
		{ "infile",    required_argument, NULL, 'i' },
		{ NULL }
	};

	int opt = 0, arg;
	bool default_at_once = true;
	double argf;
	char *argcp, *local_ip = NULL;
	while ((opt = getopt_long(argc, argv, "hVt:Q:b:rp:T::F:I:l:i:", opts, NULL)) != -1) {
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
				ERR2("invalid duration '%s'\n", optarg);
				return false;
			}
			break;
		case 'Q':
			assert(optarg);
			arg = atoi(optarg);
			if (arg > 0) {
				ctx->qps = arg;
			} else {
				ERR2("invalid QPS '%s'\n", optarg);
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
				ERR2("invalid batch size '%s'\n", optarg);
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
				ERR2("invalid port '%s'\n", optarg);
				return false;
			}
			break;
		case 'T':
			ctx->tcp = true;
			ctx->flags &= ~(KNOT_XDP_FILTER_UDP | KNOT_XDP_FILTER_QUIC);
			ctx->flags |= KNOT_XDP_FILTER_TCP;
			if (default_at_once) {
				ctx->at_once = 1;
			}
			ctx->tcp_mode = (optarg == NULL ? '0' : optarg[0]);
			switch (ctx->tcp_mode) {
			case '0':
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
				ctx->ignore2 = XDP_TCP_IGNORE_FIN;
				break;
			default:
				ERR2("invalid TCP mode '%s'\n", optarg);
				return false;
			}
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
		default:
			print_help();
			return false;
		}
	}
	if (global_payloads == NULL || argc - optind != 1) {
		print_help();
		return false;
	}

	if (!configure_target(argv[optind], local_ip, ctx)) {
		return false;
	}

	if (ctx->qps < ctx->n_threads) {
		WARN2("QPS increased to the number of threads/queues: %u\n", ctx->n_threads);
		ctx->qps = ctx->n_threads;
	}
	ctx->qps /= ctx->n_threads;

	INFO2("using interface %s, XDP threads %u, %s%s%c\n", ctx->dev, ctx->n_threads,
	      ctx->tcp ? "TCP" : "UDP",
	      (ctx->tcp && ctx->tcp_mode != '0') ? " mode " : "",
	      (ctx->tcp && ctx->tcp_mode != '0') ? ctx->tcp_mode : ' ');

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
		ERR2("out of memory\n");
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
				WARN2("unable to increase RLIMIT_MEMLOCK: %s\n",
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
			WARN2("failed to set affinity of thread#%zu to CPU#%u\n", i, affinity);
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
		print_stats(&global_stats, ctx.tcp, !(ctx.flags & KNOT_XDP_FILTER_DROP));
	}
	pthread_mutex_destroy(&global_stats.mutex);

	free(thread_ctxs);
	free(threads);
	free_global_payloads();

	return EXIT_SUCCESS;
}
