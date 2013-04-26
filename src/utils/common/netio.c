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
#include <arpa/inet.h>			// inet_ntop
#include <unistd.h>			// close

#include "utils/common/msg.h"		// WARN
#include "common/descriptor.h"		// KNOT_CLASS_IN
#include "common/errcode.h"		// KNOT_E

server_t* server_create(const char *name, const char *service)
{
	if (name == NULL || service == NULL) {
		DBG_NULL;
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

	if (server->name == NULL || server->service == NULL) {
		server_free(server);
		return NULL;
	}

	// Return result.
	return server;
}

void server_free(server_t *server)
{
	if (server == NULL) {
		DBG_NULL;
		return;
	}

	free(server->name);
	free(server->service);
	free(server);
}

static void net_clean(net_t *net)
{
	free(net->proto);
	free(net->addr);
}

int get_iptype(const ip_t ip)
{
	switch (ip) {
	case IP_4:
		return AF_INET;
	case IP_6:
		return AF_INET6;
	default:
		return AF_UNSPEC;
	}
}

int get_socktype(const protocol_t proto, const uint16_t type)
{
	switch (proto) {
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

static void net_info(net_t *net)
{
	struct sockaddr_storage ss;
	socklen_t               ss_len = sizeof(ss);
	char                    addr[INET6_ADDRSTRLEN] = "NULL";
	int                     port = -1;

	// Set connected socket type.
	switch (net->socktype) {
	case SOCK_STREAM:
		net->proto = strdup("TCP");
		break;
	case SOCK_DGRAM:
		net->proto = strdup("UDP");
		break;
	}

	// Get connected address.
	if (getpeername(net->sockfd, (struct sockaddr*)&ss, &ss_len) == 0) {
		if (ss.ss_family == AF_INET) {
			struct sockaddr_in *s = (struct sockaddr_in *)&ss;
			port = ntohs(s->sin_port);
			inet_ntop(AF_INET, &s->sin_addr, addr, sizeof(addr));
		} else { // AF_INET6
			struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ss;
			port = ntohs(s->sin6_port);
			inet_ntop(AF_INET6, &s->sin6_addr, addr, sizeof(addr));
		}
	}

	net->addr = strdup(addr);
	net->port = port;
}

int net_connect(const server_t *local,
                const server_t *remote,
                const int      iptype,
                const int      socktype,
                const int      wait,
                net_t          *net)
{
	struct addrinfo hints, *res;
	struct pollfd   pfd;
	int             sockfd, cs, err = 0;
	socklen_t       err_len = sizeof(err);

	if (remote == NULL || net == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	memset(&hints, 0, sizeof(hints));

	// Fill in relevant hints.
	hints.ai_family = iptype;
	hints.ai_socktype = socktype;

	// Get connection parameters.
	if (getaddrinfo(remote->name, remote->service, &hints, &res) != 0) {
		WARN("can't use server %s, service %s\n",
		     remote->name, remote->service);
		return KNOT_ERROR;
	}

	// Create socket.
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd == -1) {
		WARN("can't create socket for %s#%s\n",
		     remote->name, remote->service);
		freeaddrinfo(res);
		return KNOT_ERROR;
	}

	// Initialize poll descriptor structure.
	pfd.fd = sockfd;
	pfd.events = POLLOUT;
	pfd.revents = 0;

	// Set non-blocking socket.
	if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
		WARN("can't create non-blocking socket\n");
	}

	// Bind to address if specified.
	if (local != NULL) {
		struct addrinfo lhints, *lres;

		memset(&lhints, 0, sizeof(lhints));

		// Fill in relevant hints.
		lhints.ai_family = iptype;
		lhints.ai_socktype = socktype;

		// Get connection parameters.
		if (getaddrinfo(local->name, local->service, &lhints, &lres)
		    != 0) {
			WARN("can't use local %s service %s\n",
			     local->name, local->service);
		}

		// Bind to the address.
		if (bind(sockfd, lres->ai_addr, lres->ai_addrlen) == -1) {
			WARN("can't bind to %s#%s\n",
			     local->name, local->service);
		}

		// Free getaddrr data.
		freeaddrinfo(lres);
	}

	// Connect using socket.
	if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1 &&
	    errno != EINPROGRESS) {
		WARN("can't connect to %s#%s\n",
		     remote->name, remote->service);
		close(sockfd);
		freeaddrinfo(res);
		return KNOT_ERROR;
	}

	// Free getaddrr data.
	freeaddrinfo(res);

	// Check for connection timeout.
	if (poll(&pfd, 1, 1000 * wait) != 1) {
		WARN("can't wait for connection to %s#%s\n",
		     remote->name, remote->service);
		close(sockfd);
		return KNOT_ERROR;
	}

	// Check if NB socket is writeable.
	cs = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &err_len);
	if (cs < 0 || err != 0) {
		WARN("can't connect to %s#%s\n",
		     remote->name, remote->service);
		close(sockfd);
		return KNOT_ERROR;
	}

	// Fill in output.
	net->sockfd = sockfd;
	net->socktype = socktype;
	net->wait = wait;

	// Fill in additional information.
	net_info(net);

	return KNOT_EOK;
}

int net_send(const net_t *net, const uint8_t *buf, const size_t buf_len)
{
	if (net == NULL || buf == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// For TCP add leading length bytes.
	if (net->socktype == SOCK_STREAM) {
		uint16_t pktsize = htons(buf_len);

		if (send(net->sockfd, &pktsize, sizeof(pktsize), 0) !=
		    sizeof(pktsize)) {
			WARN("can't send leading TCP bytes to %s#%i\n",
			net->addr, net->port);
			return KNOT_ERROR;
		}
	}

	// Send data.
	if (send(net->sockfd, buf, buf_len, 0) != buf_len) {
		WARN("can't send query to %s#%i over %s\n",
		     net->addr, net->port, net->proto);
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int net_receive(const net_t *net, uint8_t *buf, const size_t buf_len)
{
	ssize_t       ret;
	struct pollfd pfd;

	if (net == NULL || buf == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Initialize poll descriptor structure.
	pfd.fd = net->sockfd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	if (net->socktype == SOCK_STREAM) {
		uint16_t msg_len;
		uint32_t total = 0;

		// Receive TCP message header.
		while (total < sizeof(msg_len)) {
			if (poll(&pfd, 1, 1000 * net->wait) != 1) {
				WARN("can't wait for TCP answer from %s#%i\n",
				     net->addr, net->port);
				return KNOT_ERROR;
			}

			// Receive piece of message.
			ret = recv(net->sockfd, (uint8_t *)&msg_len + total,
			           sizeof(msg_len) - total, 0);

			if (ret <= 0) {
				WARN("can't receive TCP answer from %s#%i\n",
				     net->addr, net->port);
				return KNOT_ERROR;
			}

			total += ret;
		}

		// Convert number to host format.
		msg_len = ntohs(msg_len);

		total = 0;

		// Receive whole answer message by parts.
		while (total < msg_len) {
			if (poll(&pfd, 1, 1000 * net->wait) != 1) {
				WARN("can't wait for TCP answer from %s#%i\n",
				     net->addr, net->port);
				return KNOT_ERROR;
			}

			// Receive piece of message.
			ret = recv(net->sockfd, buf + total, msg_len - total, 0);

			if (ret <= 0) {
				WARN("can't receive TCP answer from %s#%i\n",
				     net->addr, net->port);
				return KNOT_ERROR;
			}

			total += ret;
		}

		return total;
	} else {
		// Wait for datagram data.
		if (poll(&pfd, 1, 1000 * net->wait) != 1) {
			WARN("can't wait for UDP answer from %s#%i\n",
			     net->addr, net->port);
			return KNOT_ERROR;
		}

		// Receive whole UDP datagram.
		ret = recv(net->sockfd, buf, buf_len, 0);

		if (ret <= 0) {
			WARN("can't receive UDP answer from %s#%i\n",
			     net->addr, net->port);
			return KNOT_ERROR;
		}

		return ret;
	}

	return KNOT_EOK;
}

void net_close(net_t *net)
{
	if (net == NULL) {
		DBG_NULL;
		return;
	}

	close(net->sockfd);
	net_clean(net);
}
