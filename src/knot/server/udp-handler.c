/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "common/sockaddr.h"
#include "knot/common.h"
#include "knot/other/error.h"
#include "knot/server/udp-handler.h"
#include "libknot/nameserver/name-server.h"
#include "knot/stat/stat.h"
#include "knot/server/server.h"
#include "libknot/util/wire.h"
#include "libknot/consts.h"
#include "libknot/packet/packet.h"
#include "knot/server/zones.h"
#include "knot/server/notify.h"

///*! \brief Wrapper for UDP send. */
//static int xfr_send_udp(int session, sockaddr_t *addr, uint8_t *msg, size_t msglen)
//{
//	return sendto(session, msg, msglen, 0, addr->ptr, addr->len);
//}

int udp_handle(int fd, uint8_t *qbuf, size_t qbuflen, size_t *resp_len,
	       sockaddr_t* addr, knot_nameserver_t *ns)
{
	dbg_net("udp: fd=%d received %zd bytes.\n", fd, qbuflen);
	
	knot_packet_type_t qtype = KNOT_QUERY_NORMAL;
	*resp_len = SOCKET_MTU_SZ;

	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	if (packet == NULL) {
		dbg_net("udp: failed to create packet on fd=%d\n", fd);
		uint16_t pkt_id = knot_wire_get_id(qbuf);
		knot_ns_error_response(ns, pkt_id, KNOT_RCODE_SERVFAIL,
				  qbuf, resp_len);
		return KNOTD_EOK; /* Created error response. */
	}

	/* Parse query. */
	int res = knot_ns_parse_packet(qbuf, qbuflen, packet, &qtype);
	if (unlikely(res != KNOTD_EOK)) {
		dbg_net("udp: failed to parse packet on fd=%d\n", fd);
		/* Send error response on dnslib RCODE. */
		if (res > 0) {
			uint16_t pkt_id = knot_wire_get_id(qbuf);
			knot_ns_error_response(ns, pkt_id, res,
					  qbuf, resp_len);
		}

		knot_packet_free(&packet);
		return KNOTD_EOK; /* Created error response. */
	}

	/* Handle query. */
//	server_t *srv = (server_t *)knot_ns_get_data(ns);
//	knot_ns_xfr_t xfr;
	res = KNOTD_ERROR;
	switch(qtype) {

	/* Response types. */
	case KNOT_RESPONSE_NORMAL:
		res = zones_process_response(ns, addr, packet,
					     qbuf, resp_len);
		break;
	case KNOT_RESPONSE_NOTIFY:
		res = notify_process_response(ns, packet, addr,
					      qbuf, resp_len);
		break;
	
	/* Query types. */
	case KNOT_QUERY_NORMAL:
		res = knot_ns_answer_normal(ns, packet, qbuf,
					      resp_len);
		break;
	case KNOT_QUERY_AXFR:
		/* RFC1034, p.28 requires reliable transfer protocol.
		 * Bind responds with FORMERR.
 		 */
		/*! \todo Draft exists for AXFR/UDP, but has not been standardized. */
		knot_ns_error_response(ns, knot_packet_id(packet),
				       KNOT_RCODE_FORMERR, qbuf,
				       resp_len);
		res = KNOTD_EOK;
		break;
		
//		/* Process AXFR over UDP. */
//		res = xfr_request_init(&xfr, XFR_TYPE_AOUT, XFR_FLAG_UDP, packet);
//		if (res != KNOTD_EOK) {
//			knot_ns_error_response(ns, knot_packet_id(packet),
//			                       KNOT_RCODE_SERVFAIL, qbuf,
//			                       resp_len);
//			res = KNOTD_EOK;
//			break;
//		}
//		xfr.send = xfr_send_udp;
//		xfr.session = dup(fd);
//		memcpy(&xfr.addr, addr, sizeof(sockaddr_t));
//		xfr_request(srv->xfr_h, &xfr);
//		dbg_net("udp: enqueued AXFR query on fd=%d\n", xfr.session);
//		*resp_len = 0;
//		return KNOTD_EOK;
	case KNOT_QUERY_IXFR:
		/* According to RFC1035, respond with SOA. 
		 * Draft proposes trying to fit response into one packet,
		 * but I have found no tool or slave server to actually attempt
		 * IXFR/UDP.
		 */
		knot_packet_set_qtype(packet, KNOT_RRTYPE_SOA);
		res = knot_ns_answer_normal(ns, packet, qbuf,
		                            resp_len);
		break;
//		/* Process IXFR over UDP. */
//		res = xfr_request_init(&xfr, XFR_TYPE_IOUT, XFR_FLAG_UDP, packet);
//		if (res != KNOTD_EOK) {
//			knot_ns_error_response(ns, knot_packet_id(packet),
//			                       KNOT_RCODE_SERVFAIL, qbuf,
//			                       resp_len);
//			res = KNOTD_EOK;
//			break;
//		}
//		xfr.send = xfr_send_udp;
//		xfr.session = dup(fd);
//		memcpy(&xfr.addr, addr, sizeof(sockaddr_t));
//		xfr_request(srv->xfr_h, &xfr);
//		dbg_net("udp: enqueued IXFR query on fd=%d\n", xfr.session);
//		*resp_len = 0;
//		return KNOTD_EOK;
	case KNOT_QUERY_NOTIFY:
		res = notify_process_request(ns, packet, addr,
					     qbuf, resp_len);
		break;
		
	/*! \todo Implement query notify/update. */
	case KNOT_QUERY_UPDATE:
		dbg_net("udp: UPDATE query on fd=%d not implemented\n", fd);
		knot_ns_error_response(ns, knot_packet_id(packet),
				       KNOT_RCODE_NOTIMPL, qbuf,
				       resp_len);
		res = KNOTD_EOK;
		break;
		
	/* Unhandled opcodes. */
	case KNOT_RESPONSE_AXFR: /*!< Processed in XFR handler. */
	case KNOT_RESPONSE_IXFR: /*!< Processed in XFR handler. */
		knot_ns_error_response(ns, knot_packet_id(packet),
		                       KNOT_RCODE_REFUSED, qbuf,
		                       resp_len);
		res = KNOTD_EOK;
		break;
			
	/* Unknown opcodes */
	default:
		knot_ns_error_response(ns, knot_packet_id(packet),
				       KNOT_RCODE_FORMERR, qbuf,
				       resp_len);
		res = KNOTD_EOK;
		break;
	}

	knot_packet_free(&packet);

	return res;
}

static inline int udp_master_recvfrom(dthread_t *thread, stat_t *thread_stat)
{
	iohandler_t *h = (iohandler_t *)thread->data;
	knot_nameserver_t *ns = h->server->nameserver;
	int sock = dup(h->fd);

	sockaddr_t addr;
	if (sockaddr_init(&addr, h->type) != KNOTD_EOK) {
		log_server_error("Socket type %d is not supported, "
				 "IPv6 support is probably disabled.\n",
				 h->type);
		return KNOTD_ENOTSUP;
	}
	
	uint8_t qbuf[SOCKET_MTU_SZ];
	struct msghdr msg;
	memset(&msg, 0, sizeof(struct msghdr));
	struct iovec iov;
	memset(&iov, 0, sizeof(struct iovec));
	iov.iov_base = qbuf;
	iov.iov_len = SOCKET_MTU_SZ;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = addr.ptr;
	msg.msg_namelen = addr.len;

	/* Loop until all data is read. */
	ssize_t n = 0;
	while (n >= 0) {

		/* Receive packet. */
		n = recvmsg(sock, &msg, 0);

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Error and interrupt handling. */
		if (unlikely(n <= 0)) {
			if (errno != EINTR && errno != 0) {
				dbg_net("udp: recvmsg() failed: %d\n",
					  errno);
			}

			if (!(h->state & ServerRunning)) {
				break;
			} else {
				continue;
			}
		}

		/* Handle received pkt. */
		size_t resp_len = 0;
		int rc = udp_handle(sock, qbuf, n, &resp_len, &addr, ns);

		/* Send response. */
		if (rc == KNOTD_EOK && resp_len > 0) {

			dbg_net("udp: on fd=%d, sending answer size=%zd.\n",
			        sock, resp_len);

			// Send datagram
			rc = sendto(sock, qbuf, resp_len,
				    0, addr.ptr, addr.len);

			// Check result
			if (rc != (int)resp_len) {
				dbg_net("udp: sendto(): failed: %d - %d.\n",
				        rc, errno);
			}
		}
	}

	/* Free allocd resources. */
	close(sock);

	return KNOTD_EOK;
}

#ifdef ENABLE_RECVMMSG
#ifdef MSG_WAITFORONE
static inline int udp_master_recvmmsg(dthread_t *thread, stat_t *thread_stat)
{
	iohandler_t *h = (iohandler_t *)thread->data;
	knot_nameserver_t *ns = h->server->nameserver;
	int sock = dup(h->fd);

	/* Allocate batch for N packets. */
	char *iobuf = malloc(SOCKET_MTU_SZ * RECVMMSG_BATCHLEN);
	sockaddr_t *addrs = malloc(sizeof(sockaddr_t) * RECVMMSG_BATCHLEN);
	struct iovec *iov = malloc(sizeof(struct iovec) * RECVMMSG_BATCHLEN);
	struct mmsghdr *msgs = malloc(sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);

	/* Prepare batch. */
	memset(msgs, 0, sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);
	for (unsigned i = 0; i < RECVMMSG_BATCHLEN; ++i) {
		sockaddr_init(addrs + i, h->type);
		iov[i].iov_base = iobuf + i * SOCKET_MTU_SZ;
		iov[i].iov_len = SOCKET_MTU_SZ;
		msgs[i].msg_hdr.msg_iov = iov + i;
		msgs[i].msg_hdr.msg_iovlen = 1;
		msgs[i].msg_hdr.msg_name = addrs[i].ptr;
		msgs[i].msg_hdr.msg_namelen = addrs[i].len;
	}

	/* Loop until all data is read. */
	ssize_t n = 0;
	while (n >= 0) {

		/* Receive multiple messages. */
		n = recvmmsg(sock, msgs, RECVMMSG_BATCHLEN, MSG_WAITFORONE, 0);

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Error and interrupt handling. */
		if (unlikely(n <= 0)) {
			if (errno != EINTR && errno != 0) {
				dbg_net("udp: recvmmsg() failed: %d\n",
				        errno);
			}

			if (!(h->state & ServerRunning)) {
				break;
			} else {
				continue;
			}
		}

		/* Handle each received msg. */
		int ret = 0;
		for (unsigned i = 0; i < n; ++i) {
			struct iovec *cvec = msgs[i].msg_hdr.msg_iov;
			size_t resp_len = msgs[i].msg_len;
			ret = udp_handle(sock, cvec->iov_base, resp_len, &resp_len,
			                 addrs + i, ns);
			if (ret == KNOTD_EOK) {
				msgs[i].msg_len = resp_len;
			} else {
				msgs[i].msg_len = 0;
			}
			
		}

		/* Gather results. */
		/*! \todo Implement with sendmmsg() when it's ready. */
		for (unsigned i = 0; i < n; ++i) {
			const size_t resp_len = msgs[i].msg_len;
			if (resp_len > 0) {
				dbg_net("udp: on fd=%d, sending answer size=%zd.\n",
				        sock, resp_len);

				// Send datagram
				sockaddr_t *addr = addrs + i;
				struct iovec *cvec = msgs[i].msg_hdr.msg_iov;
				int res = sendto(sock, cvec->iov_base, resp_len,
						 0, addr->ptr, addr->len);

				// Check result
				if (res != (int)resp_len) {
					dbg_net("udp: sendto(): failed: %d - %d.\n",
					        res, errno);
				}
			}
		}
	}

	/* Free allocd resources. */
	free(iobuf);
	free(addrs);
	free(iov);
	free(msgs);
	close(sock);
	return KNOTD_EOK;
}
#endif
#endif

int udp_master(dthread_t *thread)
{
	iohandler_t *handler = (iohandler_t *)thread->data;
	int sock = handler->fd;

	/* Check socket. */
	if (sock < 0) {
		dbg_net("udp: null socket recevied, finishing.\n");
		return KNOTD_EINVAL;
	}

	/* Set socket options. */
	int flag = 1;
#ifndef DISABLE_IPV6
#
	if (handler->type == AF_INET6) {
		/* Disable dual-stack for performance reasons. */
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));

		/* UDP packets will not exceed a minimum MTU size. */
		/*flag = IPV6_MIN_MTU;
		setsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &flag, sizeof(flag));
		flag = 1; */
	}
#endif
	if (handler->type == AF_INET) {

//#ifdef IP_PMTUDISC_DONT
//		/* Disable fragmentation. */
//		flag = IP_PMTUDISC_DONT;
//		setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag));
//		flag = 1;
//#endif
	}

	/* in case of STAT_COMPILE the following code will declare thread_stat
	 * variable in following fashion: stat_t *thread_stat;
	 */

	stat_t *thread_stat = 0;
	STAT_INIT(thread_stat); //XXX new stat instance every time.
	stat_set_protocol(thread_stat, stat_UDP);

	/* Execute proper handler. */
	dbg_net_verb("udp: thread started (worker %p).\n", thread);
	int ret = KNOTD_EOK;

#ifdef ENABLE_RECVMMSG
	
/* Check if MSG_WAITFORONE is supported. */
#ifdef MSG_WAITFORONE
	ret = udp_master_recvmmsg(thread, thread_stat);
#else /* Don't have MSG_WAITFORONE */
	ret = udp_master_recvfrom(thread, thread_stat);
#endif
	
#else /* Don't have ENABLE_RECVMMSG */
	ret = udp_master_recvfrom(thread, thread_stat);
#endif


	stat_free(thread_stat);
	dbg_net_verb("udp: worker %p finished.\n", thread);
	return ret;
}

