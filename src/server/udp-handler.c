#include <config.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>

#include "common.h"
#include "server/udp-handler.h"
#include "server/name-server.h"
#include "stat/stat.h"
#include "server/server.h"

int udp_master(dthread_t *thread)
{
	iohandler_t *handler = (iohandler_t *)thread->data;
	ns_nameserver *ns = handler->server->nameserver;
	int sock = handler->fd;

	// Check socket
	if (sock < 0) {
		debug_net("udp_worker: null socket recevied, finishing.\n");
		return 0;
	}


	/* Set socket options. */
	int flag = 1;
	if (handler->type == AF_INET6) {
		/* Disable dual-stack for performance reasons. */
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));

		/* UDP packets will not exceed a minimum MTU size. */
		/*flag = IPV6_MIN_MTU;
		setsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &flag, sizeof(flag));
		flag = 1; */
	}
	if (handler->type == AF_INET) {

		/* Disable fragmentation. */
		flag = IP_PMTUDISC_DONT;
		setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag));
		flag = 1;
	}

	/*!
	 * \todo Use custom allocator.
	 *       Although this is much cheaper,
	 *       16kB worth of buffers *may* pose a problem.
	 */
	uint8_t inbuf[SOCKET_MTU_SZ];
	uint8_t outbuf[SOCKET_MTU_SZ];
	struct sockaddr* addr = 0;
	socklen_t addrlen = 0;

	struct sockaddr_in faddr4;
	if (handler->type == AF_INET) {
		addr = (struct sockaddr*)&faddr4;
		addrlen = sizeof(faddr4);
	}

#ifndef DISABLE_IPV6
	struct sockaddr_in6 faddr6;
	if (handler->type == AF_INET6) {
		addr = (struct sockaddr*)&faddr6;
		addrlen = sizeof(faddr6);
	}
#endif

	/*
	 * Check addr len.
	 */
	if (!addr) {
		log_server_error("UDP handler received invalid socket type %d, "
		                 "AF_INET (%d) or AF_INET6 (%d) expected.\n",
		                 handler->type, AF_INET, AF_INET6);
		return 0;
	}

	/* in case of STAT_COMPILE the following code will declare thread_stat
	 * variable in following fashion: stat_t *thread_stat;
	 */

	stat_t *thread_stat;
	STAT_INIT(thread_stat); //XXX new stat instance every time.
	stat_set_protocol(thread_stat, stat_UDP);

	// Loop until all data is read
	debug_net("udp: thread started (worker %p).\n", thread);
	int n = 0;
	while (n >= 0) {

		n = socket_recvfrom(sock, inbuf, SOCKET_MTU_SZ, 0,
		                    addr, &addrlen);

		// Cancellation point
		if (dt_is_cancelled(thread)) {
			break;
		}

		// faddr has to be read immediately.
		stat_get_first(thread_stat, addr);

		// Error and interrupt handling
		if (unlikely(n <= 0)) {
			if (errno != EINTR && errno != 0) {
				log_server_error("udp: %s: failed: %d - %s\n",
				                 "socket_recvfrom()",
				                 errno, strerror(errno));
			}

			if (!(handler->state & ServerRunning)) {
				debug_net("udp: stopping\n");
				break;
			} else {
				continue;
			}
		}

		// Answer request
		debug_net("udp: received %d bytes.\n", n);
		size_t answer_size = SOCKET_MTU_SZ;
		int res = ns_answer_request(ns, inbuf, n, outbuf,
					    &answer_size);

		debug_net("udp: got answer of size %u.\n",
			  (unsigned) answer_size);

		// Send answer
		if (res == 0) {

			assert(answer_size > 0);
			debug_net("udp: answer wire format (size %u):\n",
				  (unsigned) answer_size);
			debug_net_hex((const char *) outbuf, answer_size);

			// Send datagram
			res = socket_sendto(sock, outbuf, answer_size,
			                    0, addr, addrlen);

			// Check result
			if (res != answer_size) {
				log_server_error("udp: %s: failed: %d - %s.\n",
				                 "socket_sendto()",
				                 res, strerror(res));
				continue;
			}

			stat_get_second(thread_stat);
		}
	}

	stat_free(thread_stat);
	debug_net("udp: worker %p finished.\n", thread);
	return 0;
}

