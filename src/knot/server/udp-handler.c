/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#define __APPLE_USE_RFC_3542

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <gnutls/gnutls.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifdef HAVE_SYS_UIO_H	// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */

#ifdef LIBNGTCP2
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include "knot/server/quic-handler.h"
#endif

#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"
#include "knot/common/fdset.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "knot/server/server.h"
#include "knot/server/udp-handler.h"
#include "knot/server/xdp-handler.h"

/*! \brief UDP context data. */
typedef struct {
	knot_layer_t layer; /*!< Query processing layer. */
	server_t *server;   /*!< Name server structure. */
	unsigned thread_id; /*!< Thread identifier. */
} udp_context_t;

static bool udp_state_active(int state)
{
	return (state == KNOT_STATE_PRODUCE || state == KNOT_STATE_FAIL);
}

static void udp_handle(udp_context_t *udp, int fd, struct sockaddr_storage *ss,
                       struct iovec *rx, struct iovec *tx, struct knot_xdp_msg *xdp_msg)
{
	/* Create query processing parameter. */
	knotd_qdata_params_t params = {
		.remote = ss,
		.flags = KNOTD_QUERY_FLAG_NO_AXFR | KNOTD_QUERY_FLAG_NO_IXFR | /* No transfers. */
		         KNOTD_QUERY_FLAG_LIMIT_SIZE, /* Enforce UDP packet size limit. */
		.socket = fd,
		.server = udp->server,
		.xdp_msg = xdp_msg,
		.thread_id = udp->thread_id
	};

	/* Start query processing. */
	knot_layer_begin(&udp->layer, &params);

	/* Create packets. */
	knot_pkt_t *query = knot_pkt_new(rx->iov_base, rx->iov_len, udp->layer.mm);
	knot_pkt_t *ans = knot_pkt_new(tx->iov_base, tx->iov_len, udp->layer.mm);

	/* Input packet. */
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK && query->parsed > 0) { // parsing failed (e.g. 2x OPT)
		query->parsed--; // artificially decreasing "parsed" leads to FORMERR
	}
	knot_layer_consume(&udp->layer, query);

	/* Process answer. */
	while (udp_state_active(udp->layer.state)) {
		knot_layer_produce(&udp->layer, ans);
	}

	/* Send response only if finished successfully. */
	if (udp->layer.state == KNOT_STATE_DONE) {
		tx->iov_len = ans->size;
	} else {
		tx->iov_len = 0;
	}

	/* Reset after processing. */
	knot_layer_finish(&udp->layer);

	/* Flush per-query memory (including query and answer packets). */
	mp_flush(udp->layer.mm->ctx);
}

typedef struct {
	void* (*udp_init)(void *);
	void (*udp_deinit)(void *);
	int (*udp_recv)(int, void *);
	void (*udp_handle)(udp_context_t *, void *);
	void (*udp_send)(void *);
	void (*udp_sweep)(void *); // Optional
} udp_api_t;

static void udp_pktinfo_handle(const struct msghdr *rx, struct msghdr *tx)
{
	tx->msg_controllen = rx->msg_controllen;
	if (tx->msg_controllen > 0) {
		tx->msg_control = rx->msg_control;
	} else {
		// BSD has problem with zero length and not-null pointer
		tx->msg_control = NULL;
	}

#if defined(__linux__) || defined(__APPLE__)
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(tx);
	if (cmsg == NULL) {
		return;
	}

	/* Unset the ifindex to not bypass the routing tables. */
	if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
		struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA(cmsg);
		info->ipi_spec_dst = info->ipi_addr;
		info->ipi_ifindex = 0;
	} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
		struct in6_pktinfo *info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		info->ipi6_ifindex = 0;
	}
#endif
}

/* UDP recvfrom() request struct. */
struct udp_recvfrom {
	int fd;
	struct sockaddr_storage addr;
	struct msghdr msg[NBUFS];
	struct iovec iov[NBUFS];
	uint8_t buf[NBUFS][KNOT_WIRE_MAX_PKTSIZE];
	cmsg_pktinfo_t pktinfo;
};

static void *udp_recvfrom_init(_unused_ void *xdp_sock)
{
	struct udp_recvfrom *rq = malloc(sizeof(struct udp_recvfrom));
	if (rq == NULL) {
		return NULL;
	}
	memset(rq, 0, sizeof(struct udp_recvfrom));

	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->iov[i].iov_base = rq->buf + i;
		rq->iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
		rq->msg[i].msg_name = &rq->addr;
		rq->msg[i].msg_namelen = sizeof(rq->addr);
		rq->msg[i].msg_iov = &rq->iov[i];
		rq->msg[i].msg_iovlen = 1;
		rq->msg[i].msg_control = &rq->pktinfo.cmsg;
		rq->msg[i].msg_controllen = sizeof(rq->pktinfo);
	}
	return rq;
}

static void udp_recvfrom_deinit(void *d)
{
	struct udp_recvfrom *rq = d;
	free(rq);
}

static int udp_recvfrom_recv(int fd, void *d)
{
	/* Reset max lengths. */
	struct udp_recvfrom *rq = (struct udp_recvfrom *)d;
	rq->iov[RX].iov_len = KNOT_WIRE_MAX_PKTSIZE;
	rq->msg[RX].msg_namelen = sizeof(struct sockaddr_storage);
	rq->msg[RX].msg_controllen = sizeof(rq->pktinfo);

	int ret = recvmsg(fd, &rq->msg[RX], MSG_DONTWAIT);
	if (ret > 0) {
		rq->fd = fd;
		rq->iov[RX].iov_len = ret;
	}

	return 0;
}

static void udp_recvfrom_handle(udp_context_t *ctx, void *d)
{
	struct udp_recvfrom *rq = d;

	/* Prepare TX address. */
	rq->msg[TX].msg_namelen = rq->msg[RX].msg_namelen;
	rq->iov[TX].iov_len = KNOT_WIRE_MAX_PKTSIZE;

	udp_pktinfo_handle(&rq->msg[RX], &rq->msg[TX]);

	/* Process received pkt. */
	udp_handle(ctx, rq->fd, &rq->addr, &rq->iov[RX], &rq->iov[TX], NULL);
}

static void udp_recvfrom_send(void *d)
{
	struct udp_recvfrom *rq = d;
	if (rq->iov[TX].iov_len > 0) {
		(void)sendmsg(rq->fd, &rq->msg[TX], 0);
	}
}

_unused_
static udp_api_t udp_recvfrom_api = {
	udp_recvfrom_init,
	udp_recvfrom_deinit,
	udp_recvfrom_recv,
	udp_recvfrom_handle,
	udp_recvfrom_send,
};

#ifdef ENABLE_RECVMMSG
/* UDP recvmmsg() request struct. */
struct udp_recvmmsg {
	int fd;
	struct sockaddr_storage addrs[RECVMMSG_BATCHLEN];
	char *iobuf[NBUFS];
	struct iovec *iov[NBUFS];
	struct mmsghdr *msgs[NBUFS];
	unsigned rcvd;
	knot_mm_t mm;
	cmsg_pktinfo_t pktinfo[RECVMMSG_BATCHLEN];
};

static void *udp_recvmmsg_init(_unused_ void *xdp_sock)
{
	knot_mm_t mm;
	mm_ctx_mempool(&mm, sizeof(struct udp_recvmmsg));

	struct udp_recvmmsg *rq = mm_alloc(&mm, sizeof(struct udp_recvmmsg));
	memset(rq, 0, sizeof(*rq));
	memcpy(&rq->mm, &mm, sizeof(knot_mm_t));

	/* Initialize buffers. */
	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->iobuf[i] = mm_alloc(&mm, KNOT_WIRE_MAX_PKTSIZE * RECVMMSG_BATCHLEN);
		rq->iov[i] = mm_alloc(&mm, sizeof(struct iovec) * RECVMMSG_BATCHLEN);
		rq->msgs[i] = mm_alloc(&mm, sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);
		memset(rq->msgs[i], 0, sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);
		for (unsigned k = 0; k < RECVMMSG_BATCHLEN; ++k) {
			rq->iov[i][k].iov_base = rq->iobuf[i] + k * KNOT_WIRE_MAX_PKTSIZE;
			rq->iov[i][k].iov_len = KNOT_WIRE_MAX_PKTSIZE;
			rq->msgs[i][k].msg_hdr.msg_iov = rq->iov[i] + k;
			rq->msgs[i][k].msg_hdr.msg_iovlen = 1;
			rq->msgs[i][k].msg_hdr.msg_name = rq->addrs + k;
			rq->msgs[i][k].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
			rq->msgs[i][k].msg_hdr.msg_control = &rq->pktinfo[k].cmsg;
			rq->msgs[i][k].msg_hdr.msg_controllen = sizeof(cmsg_pktinfo_t);
		}
	}

	return rq;
}

static void udp_recvmmsg_deinit(void *d)
{
	struct udp_recvmmsg *rq = d;
	if (rq != NULL) {
		mp_delete(rq->mm.ctx);
	}
}

static int udp_recvmmsg_recv(int fd, void *d)
{
	struct udp_recvmmsg *rq = d;

	int n = recvmmsg(fd, rq->msgs[RX], RECVMMSG_BATCHLEN, MSG_DONTWAIT, NULL);
	if (n > 0) {
		rq->fd = fd;
		rq->rcvd = n;
	}
	return n;
}

static void udp_recvmmsg_handle(udp_context_t *ctx, void *d)
{
	struct udp_recvmmsg *rq = d;

	/* Handle each received msg. */
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		struct iovec *rx = rq->msgs[RX][i].msg_hdr.msg_iov;
		struct iovec *tx = rq->msgs[TX][i].msg_hdr.msg_iov;
		rx->iov_len = rq->msgs[RX][i].msg_len; /* Received bytes. */

		udp_pktinfo_handle(&rq->msgs[RX][i].msg_hdr, &rq->msgs[TX][i].msg_hdr);

		udp_handle(ctx, rq->fd, rq->addrs + i, rx, tx, NULL);
		rq->msgs[TX][i].msg_len = tx->iov_len;
		rq->msgs[TX][i].msg_hdr.msg_namelen = 0;
		if (tx->iov_len > 0) {
			/* @note sendmmsg() workaround to prevent sending the packet */
			rq->msgs[TX][i].msg_hdr.msg_namelen = rq->msgs[RX][i].msg_hdr.msg_namelen;
		}
	}
}

static void udp_recvmmsg_send(void *d)
{
	struct udp_recvmmsg *rq = d;
	(void)sendmmsg(rq->fd, rq->msgs[TX], rq->rcvd, 0);
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		/* Reset buffer size and address len. */
		struct iovec *rx = rq->msgs[RX][i].msg_hdr.msg_iov;
		struct iovec *tx = rq->msgs[TX][i].msg_hdr.msg_iov;
		rx->iov_len = KNOT_WIRE_MAX_PKTSIZE; /* Reset RX buflen */
		tx->iov_len = KNOT_WIRE_MAX_PKTSIZE;

		memset(rq->addrs + i, 0, sizeof(struct sockaddr_storage));
		rq->msgs[RX][i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
		rq->msgs[TX][i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
		rq->msgs[RX][i].msg_hdr.msg_controllen = sizeof(cmsg_pktinfo_t);
	}
}

static udp_api_t udp_recvmmsg_api = {
	udp_recvmmsg_init,
	udp_recvmmsg_deinit,
	udp_recvmmsg_recv,
	udp_recvmmsg_handle,
	udp_recvmmsg_send,
};
#endif /* ENABLE_RECVMMSG */

#ifdef ENABLE_XDP

static void *xdp_recvmmsg_init(void *xdp_sock)
{
	return xdp_handle_init(xdp_sock);
}

static void xdp_recvmmsg_deinit(void *d)
{
	xdp_handle_free(d);
}

static int xdp_recvmmsg_recv(_unused_ int fd, void *d)
{
	return xdp_handle_recv(d);
}

static void xdp_recvmmsg_handle(udp_context_t *ctx, void *d)
{
	xdp_handle_msgs(d, &ctx->layer, ctx->server, ctx->thread_id);
}

static void xdp_recvmmsg_send(void *d)
{
	xdp_handle_send(d);
}

static void xdp_recvmmsg_sweep(void *d)
{
	xdp_handle_reconfigure(d);
	xdp_handle_sweep(d);
}

static udp_api_t xdp_recvmmsg_api = {
	xdp_recvmmsg_init,
	xdp_recvmmsg_deinit,
	xdp_recvmmsg_recv,
	xdp_recvmmsg_handle,
	xdp_recvmmsg_send,
	xdp_recvmmsg_sweep,
};
#endif /* ENABLE_XDP */


static bool is_xdp_thread(const server_t *server, int thread_id)
{
	const unsigned size = server->handlers[IO_XDP].size;
	const unsigned *ids = server->handlers[IO_XDP].handler.thread_id;
	return size > 0 && thread_id >= ids[0] && thread_id <= ids[size - 1];
}

#ifdef LIBNGTCP2
static int anti_replay_db_add_func(void *dbf, time_t exp_time,
                                   const gnutls_datum_t *key,
                                   const gnutls_datum_t *data)
{
	return 0;
}

static void session_ticket_key_free(gnutls_datum_t *ticket) {
	gnutls_memset(ticket->data, 0, ticket->size);
	gnutls_free(ticket->data);
}


#include <gnutls/crypto.h>
#include "libdnssec/random.h"
#include "libdnssec/error.h"

static int quic_generate_secret(uint8_t *buf, size_t buflen) {
	assert(buf != NULL && buflen > 0 && buflen <= 32);
	uint8_t rand[16], hash[32];
	int ret = dnssec_random_buffer(rand, sizeof(rand));
	if (ret != DNSSEC_EOK) {
		return ret;
	}
	ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, rand, sizeof(rand), hash);
	if (ret != 0) {
		return ret;
	}
	memcpy(buf, hash, buflen);
	return KNOT_EOK;
}

static void *quic_recvfrom_init(_unused_ void *xdp_sock)
{
	struct quic_recvfrom *rq = malloc(sizeof(struct quic_recvfrom));
	if (rq == NULL) {
		return NULL;
	}
	memset(rq, 0, sizeof(struct quic_recvfrom));

	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->iov[i].iov_base = rq->buf + i;
		rq->iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
		rq->msg[i].msg_name = &rq->addr;
		rq->msg[i].msg_namelen = sizeof(rq->addr);
		rq->msg[i].msg_iov = &rq->iov[i];
		rq->msg[i].msg_iovlen = 1;
		rq->msg[i].msg_control = &rq->pktinfo.cmsg;
		rq->msg[i].msg_controllen = sizeof(rq->pktinfo);
	}

	// TLS certificates
	int ret = gnutls_certificate_allocate_credentials(&rq->tls_creds.tls_cert);
	if (ret != GNUTLS_E_SUCCESS) {
		free(rq);
		return NULL;
	}

	ret = gnutls_certificate_set_x509_system_trust(rq->tls_creds.tls_cert);
	if (ret < 0) {
		gnutls_certificate_free_credentials(rq->tls_creds.tls_cert);
		free(rq);
		return NULL;
	}

	conf_val_t crt_val = conf_get(conf(), C_SRV, C_QUIC_CERT_FILE);
	const char *cert_file = conf_str(&crt_val);
	crt_val = conf_get(conf(), C_SRV, C_QUIC_KEY_FILE);
	const char *key_file = conf_str(&crt_val);
	if (cert_file != NULL && key_file != NULL) {
		ret = gnutls_certificate_set_x509_key_file(rq->tls_creds.tls_cert,
		        cert_file, key_file, GNUTLS_X509_FMT_PEM);
		if (ret != GNUTLS_E_SUCCESS) {
			assert(0);
			gnutls_certificate_free_credentials(rq->tls_creds.tls_cert);
			free(rq);
			return NULL;
		}
	} else {
		assert(0);
		gnutls_certificate_free_credentials(rq->tls_creds.tls_cert);
		free(rq);
		return NULL;
	}

	ret = gnutls_session_ticket_key_generate(&rq->tls_creds.tls_ticket_key);
	if (ret != GNUTLS_E_SUCCESS) {
		gnutls_certificate_free_credentials(rq->tls_creds.tls_cert);
		free(rq);
		return NULL;
	}

	ret = gnutls_anti_replay_init(&rq->tls_creds.tls_anti_replay);
	if (ret != GNUTLS_E_SUCCESS) {
		session_ticket_key_free(&rq->tls_creds.tls_ticket_key);
		gnutls_certificate_free_credentials(rq->tls_creds.tls_cert);
		free(rq);
		return NULL;
	}
	gnutls_anti_replay_set_add_function(rq->tls_creds.tls_anti_replay,
	                                    anti_replay_db_add_func);
	gnutls_anti_replay_set_ptr(rq->tls_creds.tls_anti_replay, NULL);

	if (quic_generate_secret(rq->tls_creds.static_secret, sizeof(rq->tls_creds.static_secret)) != KNOT_EOK) {
		session_ticket_key_free(&rq->tls_creds.tls_ticket_key);
		gnutls_certificate_free_credentials(rq->tls_creds.tls_cert);
		free(rq);
		return NULL;
	}

	rq->conns = knot_quic_table_new(100); //TODO configurable

	//conf()->cache.srv_quic_secret;

	// TLS session
	// ret = gnutls_init(&rq->tls_ctx, GNUTLS_SERVER | 
	//         GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_AUTO_SEND_TICKET |
	//         GNUTLS_NO_END_OF_EARLY_DATA);
	// if (ret != 0) {
	// 	gnutls_anti_replay_deinit(rq->tls_anti_replay);
	// 	session_ticket_key_free(&rq->tls_ticket_key);
	// 	gnutls_certificate_free_credentials(rq->tls_creds);
	// 	free(rq);
	// 	return NULL;
	// }

	// ret = gnutls_priority_set_direct(rq->tls_ctx, QUIC_PRIORITIES, NULL);
	// if (ret != 0) {
	// 	gnutls_deinit(rq->tls_ctx);
	// 	gnutls_anti_replay_deinit(rq->tls_anti_replay);
	// 	session_ticket_key_free(&rq->tls_ticket_key);
	// 	gnutls_certificate_free_credentials(rq->tls_creds);
	// 	free(rq);
	// 	return NULL;
	// }

	// gnutls_datum_t ticket_key;	
	// ret = gnutls_session_ticket_key_generate(&ticket_key);
	// if (ret != 0) {
	// 	gnutls_deinit(rq->tls_ctx);
	// 	gnutls_certificate_free_credentials(rq->tls_creds);
	// 	free(rq);
	// 	return NULL;
	// }

	// ret = gnutls_session_ticket_enable_server(rq->tls_ctx, &ticket_key);
	// if (ret != 0) {
	// 	gnutls_memset(ticket_key.data, 0, ticket_key.size);
	// 	gnutls_free(ticket_key.data);
	// 	gnutls_deinit(rq->tls_ctx);
	// 	gnutls_certificate_free_credentials(rq->tls_creds);
	// 	free(rq);
	// 	return NULL;
	// }

	// gnutls_handshake_set_secret_function(rq->tls_ctx, secret_func);
	// // gnutls_handshake_set_read_function(rq->tls_ctx, read_func);
	// // gnutls_alert_set_read_function(rq->tls_ctx, alert_read_func);
	// // gnutls_handshake_set_hook_function(rq->tls_ctx, GNUTLS_HANDSHAKE_CLIENT_HELLO,
	// //                              GNUTLS_HOOK_POST, client_hello_cb);

	return rq;
}

static int quic_recvfrom_recv(int fd, void *d)
{
	//ngtcp2_cid dcid, scid;
	const uint8_t *dcid, *scid;
	size_t dcidlen, scidlen;
	ngtcp2_pkt_hd hd;
	ngtcp2_pkt_info pi;
	uint32_t version;

	/* Reset max lengths. */
	struct quic_recvfrom *rq = (struct quic_recvfrom *)d;
	rq->iov[RX].iov_len = KNOT_WIRE_MAX_PKTSIZE;
	rq->msg[RX].msg_namelen = sizeof(struct sockaddr_storage);
	rq->msg[RX].msg_controllen = sizeof(rq->pktinfo);


	size_t pktcnt = 0;
	for (; pktcnt < 10;) {

		ssize_t nread = recvmsg(fd, &rq->msg[RX], MSG_DONTWAIT);
		if (nread < 0) {
			return KNOT_NET_ERECV;
		} else if (nread == 0) {
			return 0;
		}

		++pktcnt;

		//for (int iov_i = 0; iov_i < rq->msg->msg_iovlen; ++iov_i) {}
		rq->fd = fd;
		rq->iov[RX].iov_len = nread;

		pi.ecn = knot_quic_msghdr_ecn(&rq->msg[RX], rq->addr.ss_family);
		struct sockaddr_storage locaddr;
		size_t locaddr_len = sizeof(locaddr);
		if (knot_quic_msghdr_local_addr(&rq->msg[RX], rq->addr.ss_family, &locaddr, &locaddr_len) != KNOT_EOK) {
			//std::cerr << "Unable to obtain local address" << std::endl;
			return KNOT_NET_ERECV;
		}
		
		switch (rq->addr.ss_family) {
		case AF_INET: {
			struct sockaddr_in *addr = (struct sockaddr_in *)&locaddr;
			addr->sin_port = htons(50784);
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&locaddr;
			addr->sin6_port = htons(50784);
			break;
		}
		default:
			return KNOT_NET_ERECV;
		}

		if (nread == 0) {
			continue;
		}

		int ret = 0;
		switch (ret = ngtcp2_pkt_decode_version_cid(&version, &dcid,
						&dcidlen, &scid, &scidlen,
						rq->msg[RX].msg_iov->iov_base,
						rq->msg[RX].msg_iov->iov_len, QUIC_SV_SCIDLEN)) {
		case 0:
			break;
		case NGTCP2_ERR_VERSION_NEGOTIATION:
			knot_quic_send_version_negotiation(rq);
			// knot_conn_send_version_negotiation(rq, version, scid, scidlen, dcid,
			//                 dcidlen, ep, *local_addr, &su.sa, msg.msg_namelen);
			return 0;
		default:
			return KNOT_NET_ECONNECT; //TODO maybe change return val
		}

		assert(dcidlen <= NGTCP2_MAX_CIDLEN && scidlen <= NGTCP2_MAX_CIDLEN);
		
		knot_quic_conn_t *conn = knot_quic_table_find_dcid(rq->conns, dcid, dcidlen);
		if (conn == NULL) {
			ret = ngtcp2_accept(&hd, rq->iov[RX].iov_base, rq->iov[RX].iov_len);
			switch (ret) {
			case 0:
				break;
			case NGTCP2_ERR_RETRY:
				// TODO send_retry
			case NGTCP2_ERR_VERSION_NEGOTIATION:
				// TODO	send_version_negotiation
			default:
				// TODO
				continue;
			}

			// ngtcp2_cid ocid;
			ngtcp2_cid *pocid = NULL;

			assert(hd.type == NGTCP2_PKT_INITIAL);
			
			// TODO validate addr

			const ngtcp2_path path = {
				.local = {
					.addr = (struct sockaddr *)&locaddr,
					.addrlen = locaddr_len
				},
				.remote = {
					.addr = (struct sockaddr *)rq->msg[RX].msg_name,
					.addrlen = rq->msg[RX].msg_namelen
				},
				.user_data = NULL
			};
			conn = knot_quic_conn_new(&rq->tls_creds, &path, &hd.scid, &hd.dcid, pocid, hd.version);

			switch (knot_quic_conn_on_read(rq, conn, &pi, rq->iov[RX].iov_base, rq->iov[RX].iov_len)) {
			case 0:
				break;
			//case NETWORK_ERR_RETRY:
				//send_retry(&hd, ep, *local_addr, &su.sa, msg.msg_namelen);
				//continue;
			default:
				continue;
			}

			switch (knot_quic_conn_on_write(conn)) {
			case 0:
				break;
			default:
				return KNOT_NET_ESEND;
			}

			size_t scid_num = ngtcp2_conn_get_num_scid(conn->conn);
			assert(scid_num <= 2);
			ngtcp2_cid scids[scid_num];
			scid_num = ngtcp2_conn_get_scid(conn->conn, scids);
			for (size_t i = 0; i < scid_num; ++i) {
				knot_quic_table_store(rq->conns, &scids[i], conn);
			}
			ngtcp2_cid_init(&conn->dcid, dcid, dcidlen);
			knot_quic_table_store(rq->conns, &conn->dcid, conn);

			continue;
		}

		if (ngtcp2_conn_is_in_closing_period(conn->conn)) {
			continue;
		}

		// if (h->draining()) {
		// 	continue;
		// }

		// if (auto rv = h->on_read(ep, *local_addr, &su.sa, msg.msg_namelen, &pi, buf.data(), nread); rv != 0) {
		// 	if (rv != NETWORK_ERR_CLOSE_WAIT) {
		// 		remove(h);
		// 	}
		// 	continue;
		// }

		// h->signal_write();

	}

	return 0;
}


static udp_api_t quic_recvfrom_api = {
	quic_recvfrom_init,
	udp_recvfrom_deinit,
	quic_recvfrom_recv,
	udp_recvfrom_handle,
	udp_recvfrom_send,
};
#endif /* LIBNGTCP2 */

static bool is_quic_thread(const server_t *server, int thread_id)
{
	const unsigned size = server->handlers[IO_QUIC].size;
	const unsigned *ids = server->handlers[IO_QUIC].handler.thread_id;
	return size > 0 && thread_id >= ids[0] && thread_id <= ids[size - 1];
}

static int iface_udp_fd(const iface_t *iface, int thread_id, bool quic_thread,
                        bool xdp_thread, void **xdp_socket)
{
	if (xdp_thread) {
#ifdef ENABLE_XDP
		if (thread_id <  iface->xdp_first_thread_id ||
		    thread_id >= iface->xdp_first_thread_id + iface->fd_xdp_count) {
			return -1; // Different XDP interface.
		}
		size_t xdp_wrk_id = thread_id - iface->xdp_first_thread_id;
		assert(xdp_wrk_id < iface->fd_xdp_count);
		*xdp_socket = iface->xdp_sockets[xdp_wrk_id];
		return iface->fd_xdp[xdp_wrk_id];
#else
		assert(0);
		return -1;
#endif
	} else if (quic_thread) { // QUIC thread.
		if (iface->fd_quic_count == 0) { // No QUIC interfaces.
			return -1;
		}
		if (thread_id < iface->quic_first_thread_id ||
		    thread_id >= iface->quic_first_thread_id + iface->fd_quic_count) {
			return -1; // Different QUIC interface.
		}
#ifdef ENABLE_REUSEPORT
		size_t quic_wrk_id = thread_id - iface->quic_first_thread_id;
		assert(quic_wrk_id < iface->fd_quic_count);
		return iface->fd_quic[quic_wrk_id];
#else
		return iface->fd_quic[0];
#endif
	} else { // UDP thread.
		if (iface->fd_udp_count == 0) { // No UDP interfaces.
			assert(iface->fd_xdp_count > 0);
			return -1;
		}
#ifdef ENABLE_REUSEPORT
		assert(thread_id < iface->fd_udp_count);
		return iface->fd_udp[thread_id];
#else
		return iface->fd_udp[0];
#endif
	}
}

static unsigned udp_set_ifaces(const server_t *server, size_t n_ifaces, fdset_t *fds,
                               int thread_id, void **xdp_socket)
{
	if (n_ifaces == 0) {
		return 0;
	}

	bool xdp_thread = is_xdp_thread(server, thread_id);
	bool quic_thread = is_quic_thread(server, thread_id);
	const iface_t *ifaces = server->ifaces;

	for (const iface_t *i = ifaces; i != ifaces + n_ifaces; i++) {
		int fd = iface_udp_fd(i, thread_id, quic_thread, xdp_thread, xdp_socket);
		if (fd < 0) {
			continue;
		}
		int ret = fdset_add(fds, fd, FDSET_POLLIN, NULL);
		if (ret < 0) {
			return 0;
		}
	}

	assert(!xdp_thread || fdset_get_length(fds) == 1);
	return fdset_get_length(fds);
}

int udp_master(dthread_t *thread)
{
	if (thread == NULL || thread->data == NULL) {
		return KNOT_EINVAL;
	}

	iohandler_t *handler = (iohandler_t *)thread->data;
	int thread_id = handler->thread_id[dt_get_id(thread)];

	if (handler->server->n_ifaces == 0) {
		return KNOT_EOK;
	}

	/* Set thread affinity to CPU core (same for UDP and XDP). */
	unsigned cpu = dt_online_cpus();
	if (cpu > 1) {
		unsigned cpu_mask = (dt_get_id(thread) % cpu);
		dt_setaffinity(thread, &cpu_mask, 1);
	}

	/* Choose processing API. */
	udp_api_t *api = NULL;
	if (is_xdp_thread(handler->server, thread_id)) {
#ifdef ENABLE_XDP
		api = &xdp_recvmmsg_api;
#else
		assert(0);
#endif
	} else if (is_quic_thread(handler->server, thread_id)) {
#ifdef LIBNGTCP2
		api = &quic_recvfrom_api;
#else
		assert(0);
#endif
	} else {
#ifdef ENABLE_RECVMMSG
		api = &udp_recvmmsg_api;
#else
		api = &udp_recvfrom_api;
#endif
	}
	void *api_ctx = NULL;

	/* Create big enough memory cushion. */
	knot_mm_t mm;
	mm_ctx_mempool(&mm, 16 * MM_DEFAULT_BLKSIZE);

	/* Create UDP answering context. */
	udp_context_t udp = {
		.server = handler->server,
		.thread_id = thread_id,
	};
	knot_layer_init(&udp.layer, &mm, process_query_layer());

	/* Allocate descriptors for the configured interfaces. */
	void *xdp_socket = NULL;
	size_t nifs = handler->server->n_ifaces;
	fdset_t fds;
	if (fdset_init(&fds, nifs) != KNOT_EOK) {
		goto finish;
	}
	unsigned nfds = udp_set_ifaces(handler->server, nifs, &fds,
	                               thread_id, &xdp_socket);
	if (nfds == 0) {
		goto finish;
	}

	/* Initialize the networking API. */
	api_ctx = api->udp_init(xdp_socket);
	if (api_ctx == NULL) {
		goto finish;
	}

	/* Loop until all data is read. */
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
			if (api->udp_recv(fdset_it_get_fd(&it), api_ctx) > 0) {
				api->udp_handle(&udp, api_ctx);
				api->udp_send(api_ctx);
			}
		}

		/* Regular maintenance (XDP-TCP only). */
		if (api->udp_sweep != NULL) {
			api->udp_sweep(api_ctx);
		}
	}

finish:
	api->udp_deinit(api_ctx);
	mp_delete(mm.ctx);
	fdset_clear(&fds);

	return KNOT_EOK;
}
