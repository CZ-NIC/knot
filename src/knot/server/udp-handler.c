#include <config.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "common/sockaddr.h"
#include "knot/common.h"
#include "knot/other/error.h"
#include "knot/server/udp-handler.h"
#include "dnslib/name-server.h"
#include "knot/stat/stat.h"
#include "knot/server/server.h"
#include "dnslib/wire.h"
#include "dnslib/consts.h"
#include "dnslib/packet.h"
#include "knot/server/zones.h"
#include "knot/server/notify.h"

int udp_master(dthread_t *thread)
{
	iohandler_t *handler = (iohandler_t *)thread->data;
	knot_nameserver_t *ns = handler->server->nameserver;
	int sock = handler->fd;

	/* Check socket. */
	if (sock < 0) {
		debug_net("udp_master: null socket recevied, finishing.\n");
		return KNOTDEINVAL;
	}


	sockaddr_t addr;
	if (sockaddr_init(&addr, handler->type) != KNOTDEOK) {
		log_server_error("Socket type %d is not supported, "
				 "IPv6 support is probably disabled.\n",
				 handler->type);
		return KNOTDENOTSUP;
	}

	/* Set socket options. */
	int flag = 1;
#ifndef DISABLE_IPV6
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

#ifdef IP_PMTUDISC_DONT
		/* Disable fragmentation. */
		flag = IP_PMTUDISC_DONT;
		setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag));
		flag = 1;
#endif
	}

	/* in case of STAT_COMPILE the following code will declare thread_stat
	 * variable in following fashion: stat_t *thread_stat;
	 */

	stat_t *thread_stat = 0;
	STAT_INIT(thread_stat); //XXX new stat instance every time.
	stat_set_protocol(thread_stat, stat_UDP);

	// Loop until all data is read
	debug_net("udp: thread started (worker %p).\n", thread);
	int res = 0;
	ssize_t n = 0;
	uint8_t qbuf[SOCKET_MTU_SZ];
	knot_packet_type_t qtype = KNOT_QUERY_NORMAL;
	while (n >= 0) {

		n = recvfrom(sock, qbuf, sizeof(qbuf), 0,
			       addr.ptr, &addr.len);

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* faddr has to be read immediately. */
		stat_get_first(thread_stat, addr.ptr);

		/* Error and interrupt handling. */
		if (unlikely(n <= 0)) {
			if (errno != EINTR && errno != 0) {
				debug_net("udp: recvfrom() failed: %d\n",
					  errno);
			}

			if (!(handler->state & ServerRunning)) {
				debug_net("udp: stopping\n");
				break;
			} else {
				continue;
			}
		}

		debug_net("udp: received %zd bytes.\n", n);

		size_t resp_len = sizeof(qbuf);

		//knot_response_t *resp = knot_response_new(4 * 1024); // 4K
		knot_packet_t *packet =
			knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
		if (packet == NULL) {
			uint16_t pkt_id = knot_wire_get_id(qbuf);
			knot_ns_error_response(ns, pkt_id, KNOT_RCODE_SERVFAIL,
			                  qbuf, &resp_len);
			continue;
		}

		/* Parse query. */
		res = knot_ns_parse_packet(qbuf, n, packet, &qtype);
		if (unlikely(res != KNOTDEOK)) {
			debug_net("udp: sending back error response.\n");
			/* Send error response on dnslib RCODE. */
			if (res > 0) {
				uint16_t pkt_id = knot_wire_get_id(qbuf);
				knot_ns_error_response(ns, pkt_id, res,
				                  qbuf, &resp_len);
			}

			knot_packet_free(&packet);
			continue;
		}

		/* Handle query. */
		res = KNOTDERROR;
		switch(qtype) {

		/* Response types. */
		case KNOT_RESPONSE_NORMAL:
			res = zones_process_response(ns, &addr, packet,
			                             qbuf, &resp_len);
//			res = knot_ns_process_response();
			break;
		case KNOT_RESPONSE_AXFR:
		case KNOT_RESPONSE_IXFR:
		case KNOT_RESPONSE_NOTIFY:
			res = notify_process_response(ns, packet, &addr,
			                              qbuf, &resp_len);
			break;

		/* Query types. */
		case KNOT_QUERY_NORMAL:
			res = knot_ns_answer_normal(ns, packet, qbuf, 
			                              &resp_len);
			break;
		case KNOT_QUERY_AXFR:
		case KNOT_QUERY_IXFR:
			/*! \todo Send error, not available on UDP. */
			break;
		case KNOT_QUERY_NOTIFY:
			rcu_read_lock();
//			const knot_zone_t *zone = NULL;
//			res = knot_ns_answer_notify(ns, packet, qbuf, 
//			                              &resp_len, &zone);
			res = notify_process_request(ns, packet, &addr,
			                             qbuf, &resp_len);
//			if (res == KNOT_EOK) {
//				res = zones_notify_schedule(zone, &addr);
//			}
			break;
		case KNOT_QUERY_UPDATE:
			/*! \todo Implement query notify/update. */
			break;
		}

		knot_packet_free(&packet);

		/* Send answer. */
		if (res == KNOTDEOK && resp_len > 0) {

			debug_net("udp: got answer of size %zd.\n", resp_len);

			//debug_net("udp: answer wire format (size %zd):\n",
			//	  resp_len);
			//debug_net_hex((const char *) outbuf, resp_len);

			// Send datagram
			res = sendto(sock, qbuf, resp_len,
			             0, addr.ptr, addr.len);

			// Check result
			if (res != (int)resp_len) {
				debug_net("udp: %s: failed: %d - %d.\n",
				          "socket_sendto()",
				          res, errno);
				continue;
			}

			stat_get_second(thread_stat);
		}
	}

	stat_free(thread_stat);
	debug_net("udp: worker %p finished.\n", thread);
	return KNOTDEOK;
}

