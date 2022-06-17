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

#if defined(ENABLE_XDP) && defined(ENABLE_XDP_QUIC)

#include "contrib/ucw/mempool.h"
#include "knot/common/log.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "knot/server/server.h"
#include "libknot/xdp/quic.h"

#define QUIC_MAX_SEND_PER_RECV 4

// copied from udp-handler.c
typedef union {
	struct cmsghdr cmsg;
	uint8_t buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
} cmsg_pktinfo_t;

static int get_dest_address(struct msghdr *mh, int sock_fd, uint16_t port_be16, struct sockaddr_storage *out)
{
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(mh); cmsg != NULL; cmsg = CMSG_NXTHDR(mh, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
			struct sockaddr_in *out4 = (struct sockaddr_in *)out;
			out4->sin_family = AF_INET;
			out4->sin_port = port_be16;
			memcpy(&out4->sin_addr, &pi->ipi_addr, sizeof(pi->ipi_addr));
			return KNOT_EOK;
		} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo *pi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			struct sockaddr_in6 *out6 = (struct sockaddr_in6 *)out;
			out6->sin6_family = AF_INET6;
			out6->sin6_port = port_be16;
			memcpy(&out6->sin6_addr, &pi6->ipi6_addr, sizeof(pi6->ipi6_addr));
			return KNOT_EOK;
		}
	}
	return KNOT_ERROR;
}

static bool tcp_active_state(int state)
{
	return (state == KNOT_STATE_PRODUCE || state == KNOT_STATE_FAIL);
}

static bool tcp_send_state(int state)
{
	return (state != KNOT_STATE_FAIL && state != KNOT_STATE_NOOP);
}

static unsigned quic_set_ifaces(const iface_t *ifaces, size_t n_ifaces,
                                fdset_t *fds, int thread_id)
{
	if (n_ifaces == 0) {
		return 0;
	}

	int normal_threads = 0;

	for (const iface_t *i = ifaces; i != ifaces + n_ifaces; i++) {
		if (i->fd_tcp_count > 0) {
			normal_threads += 2; // one UDP, one TCP
		}

		if (i->fd_tcp_count > 0 || i->fd_xdp_count > 0) {
			continue;
		}

		int quic_id = 0;
#ifdef ENABLE_REUSEPORT
		if (1) {
			quic_id = thread_id - normal_threads;
		}
#endif

		int ret = fdset_add(fds, i->fd_udp[quic_id], FDSET_POLLIN, NULL);
		if (ret < 0) {
			return 0;
		}
	}

	return fdset_get_length(fds);
}

static void handle_init(knotd_qdata_params_t *params, knot_layer_t *layer,
                        const struct iovec *payload)
{
	knot_layer_begin(layer, params);

	knot_pkt_t *query = knot_pkt_new(payload->iov_base, payload->iov_len, layer->mm);
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK && query->parsed > 0) { // parsing failed (e.g. 2x OPT)
		query->parsed--; // artificially decreasing "parsed" leads to FORMERR
	}
	knot_layer_consume(layer, query);
}

static void handle_finish(knot_layer_t *layer)
{
	knot_layer_finish(layer);
	mp_flush(layer->mm->ctx);
}


static void handle_quic_stream(knot_xquic_conn_t *conn, int64_t stream_id, struct iovec *inbuf,
                               knot_layer_t *layer, knotd_qdata_params_t *params, uint8_t *ans_buf,
                               size_t ans_buf_size)
{
	// Consume the query.
	handle_init(params, layer, inbuf);

	// Process the reply.
	knot_pkt_t *ans = knot_pkt_new(ans_buf, ans_buf_size, layer->mm);
	while (tcp_active_state(layer->state)) {
		knot_layer_produce(layer, ans);
		if (!tcp_send_state(layer->state)) {
			continue;
		}
		if (knot_xquic_stream_add_data(conn, stream_id, ans->wire, ans->size) == NULL) {
			break;
		}
	}

	handle_finish(layer);
}

static int handle_quic(knot_xquic_table_t *table, int udp_fd, struct msghdr *msg,
                       uint64_t idle_timeout, knot_layer_t *layer, server_t *server,
                       struct sockaddr_storage *local_ip, int thread_id)
{
	size_t msg_quic_count = 0;
	knot_xquic_reply_ctx_t rctx = { .udp_fd = udp_fd, .udp_query = msg, .local_ip = local_ip };
	knot_xquic_conn_t *rl = NULL;
	int ret = knot_xquic_handle(table, &rctx, idle_timeout, &rl);

	if (ret == KNOT_EOK) {
		uint8_t buf[KNOT_WIRE_MAX_PKTSIZE];
		knotd_qdata_params_t params = {
			.socket = udp_fd,
			.server = server,
			.thread_id = thread_id,
			.remote = (const struct sockaddr_storage *)msg->msg_name,
		};

		int64_t stream_id;
		knot_xquic_stream_t *stream;

		while (rl != NULL && msg_quic_count < QUIC_MAX_SEND_PER_RECV &&
		       (stream = knot_xquic_stream_get_process(rl, &stream_id)) != NULL) {
			assert(stream->inbuf_fin);
			assert(stream->inbuf.iov_len > 0);
			handle_quic_stream(rl, stream_id, &stream->inbuf, layer, &params,
					   buf, KNOT_WIRE_MAX_PKTSIZE);
			stream->inbuf.iov_len = 0;
			stream->inbuf_fin = false;
		}

	}

	return knot_xquic_send(table, rl, &rctx, ret, QUIC_MAX_SEND_PER_RECV, false);
}

int quic_master(dthread_t *thread)
{
	if (thread == NULL || thread->data == NULL) {
		return KNOT_EINVAL;
	}

	iohandler_t *handler = (iohandler_t *)thread->data;
	int thread_id = handler->thread_id[dt_get_id(thread)];

	knot_mm_t mm;
	mm_ctx_mempool(&mm, 16 * MM_DEFAULT_BLKSIZE);

	knot_layer_t layer = { 0 };
	knot_layer_init(&layer, &mm, process_query_layer());

	/* Allocate descriptors for the configured interfaces. */
	size_t nifs = handler->server->n_ifaces;
	fdset_t fds;
	if (fdset_init(&fds, nifs) != KNOT_EOK) {
		goto finish;
	}
	unsigned nfds = quic_set_ifaces(handler->server->ifaces, nifs, &fds, thread_id);
	if (nfds == 0) {
		goto finish;
	}
	uint16_t port_be = ((struct sockaddr_in6 *)&handler->server->ifaces[1].addr)->sin6_port; // FIXME this must be somehow organized for ifaces separately!

	uint8_t buf[2 * KNOT_WIRE_MAX_PKTSIZE];
	struct iovec iov_in = { .iov_base = buf + KNOT_WIRE_MAX_PKTSIZE };
	cmsg_pktinfo_t pktinfo = { 0 };
	struct sockaddr_storage remote_ip, local_ip;
	struct msghdr mh_in = { .msg_iovlen = 1, .msg_iov = &iov_in, .msg_control = &pktinfo, .msg_name = &remote_ip };

	conf_t *pconf = conf();
	size_t quic_max_conns = pconf->cache.xdp_tcp_max_clients / pconf->cache.srv_quic_threads;
	size_t quic_max_obufs = pconf->cache.xdp_tcp_outbuf_max_size / pconf->cache.srv_quic_threads;
	size_t udp_pl = MIN(pconf->cache.srv_udp_max_payload_ipv4, pconf->cache.srv_udp_max_payload_ipv6);
	uint64_t quic_idle_timeout = pconf->cache.xdp_tcp_idle_close * 1000000;

	char *tls_cert = conf_tls(pconf, C_TLS_CERT);
	char *tls_key = conf_tls(pconf, C_TLS_KEY);

	knot_xquic_table_t *table = knot_xquic_table_new(quic_max_conns, udp_pl, tls_cert, tls_key);
	free(tls_cert);
	free(tls_key);
	if (table == NULL) {
		goto finish;
	}
	table->log = conf_get_bool(pconf, C_XDP, C_QUIC_LOG);

	for (;;) {
		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Wait for events. */
		fdset_it_t it;
		(void)fdset_poll(&fds, &it, 0, 1000);

		/* Process the events. */
		for (; !fdset_it_is_done(&it); fdset_it_next(&it)) {
			if (!fdset_it_is_pollin(&it)) {
				continue;
			}

			mh_in.msg_namelen = sizeof(remote_ip);
			mh_in.msg_controllen = sizeof(pktinfo);
			iov_in.iov_len = KNOT_WIRE_MAX_PKTSIZE;

			int fd = fdset_it_get_fd(&it);
			int ret = recvmsg(fd, &mh_in, MSG_DONTWAIT);
			if (ret > 0) {
				iov_in.iov_len = ret;
				ret = get_dest_address(&mh_in, fd, port_be, &local_ip);
				if (ret != KNOT_EOK) {
					continue;
				}

				(void)handle_quic(table, fd, &mh_in, quic_idle_timeout,
				                  &layer, handler->server, &local_ip, thread_id);
			}
		}

		size_t to = 0, fc = 0;
		knot_xquic_table_sweep(table, quic_max_conns, quic_max_obufs, &to, &fc);
		if (to > 0 || fc > 0) {
			log_notice("QUIC, connection timeout %zu, forcibly closed %zu", to, fc);
		}
	}

finish:
	knot_xquic_table_free(table);
	mp_delete(mm.ctx);
	fdset_clear(&fds);

	return KNOT_EOK;
}

#endif // ENABLE_XDP && ENABLE_XDP_QUIC
