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

#include "knot/common.h"
#include "knot/other/error.h"
#include "knot/server/udp-handler.h"
#include "knot/server/name-server.h"
#include "knot/stat/stat.h"
#include "knot/server/server.h"
#include "dnslib/packet.h"

int udp_master(dthread_t *thread)
{
	iohandler_t *handler = (iohandler_t *)thread->data;
	ns_nameserver_t *ns = handler->server->nameserver;
	int sock = handler->fd;

	/* Check socket. */
	if (sock < 0) {
		debug_net("udp_master: null socket recevied, finishing.\n");
		return KNOT_EINVAL;
	}


	sockaddr_t addr;
	if (socket_initaddr(&addr, handler->type) != KNOT_EOK) {
		log_server_error("Socket type %d is not supported, "
				 "IPv6 support is probably disabled.\n",
				 handler->type);
		return KNOT_ENOTSUP;
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

		/* Disable fragmentation. */
		flag = IP_PMTUDISC_DONT;
		setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag));
		flag = 1;
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
	dnslib_query_t qtype = DNSLIB_QUERY_NORMAL;
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

		dnslib_response_t *resp = dnslib_response_new(4 * 1024); // 4K
		size_t resp_len = sizeof(qbuf);

		/* Parse query. */
		res = ns_parse_query(qbuf, n, resp, &qtype);
		if (unlikely(res < 0)) {

			/* Send error response. */
			if (res != KNOT_EMALF ) {
				uint16_t pkt_id = dnslib_packet_get_id(qbuf);
				ns_error_response(ns, pkt_id, res,
						  qbuf, &resp_len);
			}

			dnslib_response_free(&resp);
			continue;
		}

		/* Handle query. */
		switch(qtype) {
		case DNSLIB_QUERY_NORMAL:
			res = ns_answer_normal(ns, resp, qbuf, &resp_len);
			break;
		case DNSLIB_QUERY_AXFR:
		case DNSLIB_QUERY_IXFR:
			/*! \todo Send error, not available on UDP. */
			break;
		case DNSLIB_QUERY_NOTIFY:
		case DNSLIB_QUERY_UPDATE:
			/*! \todo Implement query notify/update. */
			break;
		}

		debug_net("udp: got answer of size %zd.\n",
			  resp_len);

		dnslib_response_free(&resp);

		/* Send answer. */
		if (res == KNOT_EOK) {

			assert(resp_len > 0);
			debug_net("udp: answer wire format (size %zd):\n",
				  (unsigned) answer_size);
			debug_net_hex((const char *) outbuf, resp_len);

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
	return KNOT_EOK;
}

