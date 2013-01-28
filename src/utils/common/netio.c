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

#include "utils/common/netio.h"

#include <stdlib.h>			// free
#include <netdb.h>			// addrinfo
#include <poll.h>			// poll
#include <fcntl.h>			// fcntl
#include <sys/socket.h>			// AF_INET (BSD)
#include <netinet/in.h>			// ntohl (BSD)

#include "utils/common/msg.h"		// WARN
#include "libknot/util/descriptor.h"	// KNOT_CLASS_IN
#include "common/errcode.h"		// KNOT_E

server_t* server_create(const char *name, const char *service)
{
	if (name == NULL || service == NULL) {
		return NULL;
	}

	// Create output structure.
	server_t *server = calloc(1, sizeof(server_t));

	// Check output.
	if (server == NULL) {
		return NULL;
	}

	// Fill output.
	server->name = strdup(name);
	server->service = strdup(service);

	// Return result.
	return server;
}

void server_free(server_t *server)
{
	if (server == NULL) {
		return;
	}

	free(server->name);
	free(server->service);
	free(server);
}

int get_socktype(const params_t *params, const uint16_t type)
{
	if (params == NULL) {
		return KNOT_EINVAL;
	}

	switch (params->protocol) {
	case PROTO_TCP:
		return SOCK_STREAM;
	case PROTO_UDP:
		if (type == KNOT_RRTYPE_AXFR || type == KNOT_RRTYPE_IXFR) {
			WARN("using UDP for zone transfer\n");
		}
		return SOCK_DGRAM;
	default:
		if (type == KNOT_RRTYPE_AXFR || type == KNOT_RRTYPE_IXFR) {
			return SOCK_STREAM;
		} else {
			return SOCK_DGRAM;
		}
	}
}

int send_msg(const params_t *params,
             const uint16_t  type,
             const server_t *server,
             const uint8_t  *buf,
             const size_t   buf_len)
{
	struct addrinfo hints, *res;
	struct pollfd pfd;
	int sockfd;

	if (params == NULL || server == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	memset(&hints, 0, sizeof hints);

	// Set IP type.
	if (params->ip == IP_4) {
		hints.ai_family = AF_INET;
	} else if (params->ip == IP_6) {
		hints.ai_family = AF_INET6;
	} else {
		hints.ai_family = AF_UNSPEC;
	}

	// Set TCP or UDP.
	hints.ai_socktype = get_socktype(params, type);

	// Get connection parameters.
	if (getaddrinfo(server->name, server->service, &hints, &res) != 0) {
		WARN("can't use nameserver %s port %s\n",
		     server->name, server->service);
		return -1;
	}

	// Create socket.
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	if (sockfd == -1) {
		WARN("can't create socket for nameserver %s port %s\n",
		     server->name, server->service);
		return -1;
	}

	// Initialize poll descriptor structure.
	pfd.fd = sockfd;
	pfd.events = POLLOUT;
	pfd.revents = 0;

	// Set non-blocking socket.
	if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
		WARN("can't create non-blocking socket\n");
	}

	// Connect using socket.
	if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1 &&
	    errno != EINPROGRESS) {
		WARN("can't connect to nameserver %s port %s\n",
		     server->name, server->service);
		shutdown(sockfd, SHUT_RDWR);
		return -1;
	}

	// Check for connection timeout.
	if (poll(&pfd, 1, 1000 * params->wait) != 1) {
		WARN("can't wait for connection to nameserver %s port %s\n",
		     server->name, server->service);
		shutdown(sockfd, SHUT_RDWR);
		return -1;
	}
	
	// Check if socket is writeable (waited for NB connect)
	int err = 0;
	socklen_t elen = sizeof(err);
	int cs = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &elen);
	if (cs < 0 || err != 0) {
		WARN("can't connect to nameserver %s port %s\n",
		     server->name, server->service);
		shutdown(sockfd, SHUT_RDWR);
		return -1;
	}
	
	// For TCP add leading length bytes.
	if (hints.ai_socktype == SOCK_STREAM) {
		uint16_t pktsize = htons(buf_len);

		if (send(sockfd, &pktsize, sizeof(pktsize), 0) !=
		    sizeof(pktsize)) {
			WARN("TCP packet leading lenght\n");
		}
	}

	// Send data.
	if (send(sockfd, buf, buf_len, 0) != buf_len) {
		WARN("can't send query\n");
	}

	// Free getaddrr data.
	freeaddrinfo(res);

	return sockfd;
}

int receive_msg(const params_t *params,
                const uint16_t  type,
                int            sockfd,
                uint8_t        *buf,
                const size_t   buf_len)
{
	ssize_t       ret;
	struct pollfd pfd;

	if (params == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	// Initialize poll descriptor structure.
	pfd.fd = sockfd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	if (get_socktype(params, type) == SOCK_STREAM) {
		uint16_t msg_len;
		uint32_t total = 0;

		// Wait for data.
		if (poll(&pfd, 1, 1000 * params->wait) != 1) {
			WARN("can't wait for TCP message length\n");
			return KNOT_ERROR;
		}

		// Receive TCP message header.
		if (recv(sockfd, &msg_len, sizeof(msg_len), 0) !=
		    sizeof(msg_len)) {
			WARN("can't receive TCP message length\n");
			return KNOT_ERROR;
		}

		// Convert number to host format.
		msg_len = ntohs(msg_len);

		// Receive whole answer message by parts.
		while (total < msg_len) {
			if (poll(&pfd, 1, 1000 * params->wait) != 1) {
				WARN("can't wait for TCP answer\n");
				return KNOT_ERROR;
			}

			// Receive piece of message.
			ret = recv(sockfd, buf + total, msg_len - total, 0);

			if (ret <= 0) {
				WARN("can't receive TCP answer\n");
				return KNOT_ERROR;
			}

			total += ret;
		}

		return total;
	} else {
		// Wait for datagram data.
		if (poll(&pfd, 1, 1000 * params->wait) != 1) {
			WARN("can't wait for UDP answer\n");
			return KNOT_ERROR;
		}

		// Receive whole UDP datagram.
		ret = recv(sockfd, buf, buf_len, 0);

		if (ret <= 0) {
			WARN("can't receive UDP answer\n");
			return KNOT_ERROR;
		}

		return ret;
	}

	return KNOT_EOK;
}
