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
#include "utils/common/netio.h"

#include <stdlib.h>			// free
#include <netdb.h>			// addrinfo
#include <poll.h>			// poll
#include <fcntl.h>			// fcntl
#include <sys/socket.h>			// AF_INET (BSD)
#include <netinet/in.h>			// ntohl (BSD)
#include <arpa/inet.h>			// inet_ntop
#include <unistd.h>			// close
#ifdef HAVE_SYS_UIO_H			// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif // HAVE_SYS_UIO_H

#include "utils/common/msg.h"		// WARN
#include "common/descriptor.h"		// KNOT_CLASS_IN
#include "common/errcode.h"		// KNOT_E

srv_info_t* srv_info_create(const char *name, const char *service)
{
	if (name == NULL || service == NULL) {
		DBG_NULL;
		return NULL;
	}

	// Create output structure.
	srv_info_t *server = calloc(1, sizeof(srv_info_t));

	// Check output.
	if (server == NULL) {
		return NULL;
	}

	// Fill output.
	server->name = strdup(name);
	server->service = strdup(service);

	if (server->name == NULL || server->service == NULL) {
		srv_info_free(server);
		return NULL;
	}

	// Return result.
	return server;
}

void srv_info_free(srv_info_t *server)
{
	if (server == NULL) {
		DBG_NULL;
		return;
	}

	free(server->name);
	free(server->service);
	free(server);
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
		return SOCK_DGRAM;
	default:
		if (type == KNOT_RRTYPE_AXFR || type == KNOT_RRTYPE_IXFR) {
			return SOCK_STREAM;
		} else {
			return SOCK_DGRAM;
		}
	}
}

const char* get_sockname(const int socktype)
{
	const char *proto;

	switch (socktype) {
	case SOCK_STREAM:
		proto = "TCP";
		break;
	case SOCK_DGRAM:
		proto = "UDP";
		break;
	default:
		proto = "UNKNOWN";
		break;
	}

	return proto;
}

static int get_addr(const srv_info_t *server,
                    const int        iptype,
                    const int        socktype,
                    struct addrinfo  **info)
{
	struct addrinfo hints;

	// Set connection hints.
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = iptype;
	hints.ai_socktype = socktype;

	// Get connection parameters.
	if (getaddrinfo(server->name, server->service, &hints, info) != 0) {
		ERR("can't resolve address %s#%s\n",
		    server->name, server->service);
		return -1;
	}

	return 0;
}

static void get_addr_str(const struct sockaddr_storage *ss,
                         const int                     socktype,
                         char                          **dst)
{
	char     addr[INET6_ADDRSTRLEN] = "NULL";
	char     buf[128] = "NULL";
	uint16_t port;

	// Get network address string and port number.
	if (ss->ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)ss;
		inet_ntop(ss->ss_family, &s->sin_addr, addr, sizeof(addr));
		port = ntohs(s->sin_port);
	} else {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss;
		inet_ntop(ss->ss_family, &s->sin6_addr, addr, sizeof(addr));
		port = ntohs(s->sin6_port);
	}

	// Free previous string if any.
	free(*dst);
	*dst = NULL;

	// Write formated information string.
	int ret = snprintf(buf, sizeof(buf), "%s#%u(%s)", addr, port,
	                   get_sockname(socktype));
	if (ret > 0) {
		*dst = strdup(buf);
	} else {
		*dst = strdup("NULL");
	}
}

int net_init(const srv_info_t *local,
             const srv_info_t *remote,
             const int        iptype,
             const int        socktype,
             const int        wait,
             net_t            *net)
{
	if (remote == NULL || net == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Clean network structure.
	memset(net, 0, sizeof(*net));

	// Get remote address list.
	if (get_addr(remote, iptype, socktype, &net->remote_info) != 0) {
		return KNOT_NET_EADDR;
	}

	// Set current remote address.
	net->srv = net->remote_info;

	// Get local address if specified.
	if (local != NULL) {
		if (get_addr(local, iptype, socktype, &net->local_info) != 0) {
			return KNOT_NET_EADDR;
		}
	}

	// Store network parameters.
	net->iptype = iptype;
	net->socktype = socktype;
	net->wait = wait;
	net->local = local;
	net->remote = remote;

	return KNOT_EOK;
}

int net_connect(net_t *net)
{
	struct pollfd pfd;
	int           sockfd, cs, err = 0;
	socklen_t     err_len = sizeof(err);

	if (net == NULL || net->srv == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Set remote information string.
	get_addr_str((struct sockaddr_storage *)net->srv->ai_addr,
	             net->socktype, &net->remote_str);

	// Create socket.
	sockfd = socket(net->srv->ai_family, net->socktype, 0);
	if (sockfd == -1) {
		WARN("can't create socket for %s\n", net->remote_str);
		return KNOT_NET_ESOCKET;
	}

	// Initialize poll descriptor structure.
	pfd.fd = sockfd;
	pfd.events = POLLOUT;
	pfd.revents = 0;

	// Set non-blocking socket.
	if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
		WARN("can't set non-blocking socket for %s\n", net->remote_str);
		return KNOT_NET_ESOCKET;
	}

	// Bind address to socket if specified.
	if (net->local_info != NULL) {
		// Set local information string.
		get_addr_str((struct sockaddr_storage *)net->local_info->ai_addr,
		             net->socktype, &net->local_str);

		if (bind(sockfd, net->local_info->ai_addr,
		         net->local_info->ai_addrlen) == -1) {
			WARN("can't assign address %s\n", net->local_str);
			return KNOT_NET_ESOCKET;
		}
	}

	if (net->socktype == SOCK_STREAM) {
		// Connect using socket.
		if (connect(sockfd, net->srv->ai_addr, net->srv->ai_addrlen)
		    == -1 && errno != EINPROGRESS) {
			WARN("can't connect to %s\n", net->remote_str);
			close(sockfd);
			return KNOT_NET_ECONNECT;
		}

		// Check for connection timeout.
		if (poll(&pfd, 1, 1000 * net->wait) != 1) {
			WARN("connection timeout for %s\n", net->remote_str);
			close(sockfd);
			return KNOT_NET_ECONNECT;
		}

		// Check if NB socket is writeable.
		cs = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &err_len);
		if (cs < 0 || err != 0) {
			WARN("can't connect to %s\n", net->remote_str);
			close(sockfd);
			return KNOT_NET_ECONNECT;
		}
	}

	// Store socket descriptor.
	net->sockfd = sockfd;

	return KNOT_EOK;
}

int net_send(const net_t *net, const uint8_t *buf, const size_t buf_len)
{
	if (net == NULL || buf == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	if (net->socktype == SOCK_STREAM) {
		struct iovec iov[2];

		// Leading packet length bytes.
		uint16_t pktsize = htons(buf_len);

		iov[0].iov_base = &pktsize;
		iov[0].iov_len = sizeof(pktsize);
		iov[1].iov_base = (uint8_t *)buf;
		iov[1].iov_len = buf_len;

		// Compute packet total length.
		ssize_t total = iov[0].iov_len + iov[1].iov_len;

		// Send data.
		if (writev(net->sockfd, iov, 2) != total) {
			WARN("can't send query to %s\n", net->remote_str);
			return KNOT_NET_ESEND;
		}
	} else {
		// Send data.
		if (sendto(net->sockfd, buf, buf_len, 0, net->srv->ai_addr,
		           net->srv->ai_addrlen) != (ssize_t)buf_len) {
			WARN("can't send query to %s\n", net->remote_str);
			return KNOT_NET_ESEND;
		}
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
		uint16_t msg_len = 0;
		uint32_t total = 0;

		// Receive TCP message header.
		while (total < sizeof(msg_len)) {
			if (poll(&pfd, 1, 1000 * net->wait) != 1) {
				WARN("response timeout for %s\n",
				     net->remote_str);
				return KNOT_NET_ETIMEOUT;
			}

			// Receive piece of message.
			ret = recv(net->sockfd, (uint8_t *)&msg_len + total,
			           sizeof(msg_len) - total, 0);
			if (ret <= 0) {
				WARN("can't receive reply from %s\n",
				     net->remote_str);
				return KNOT_NET_ERECV;
			}

			total += ret;
		}

		// Convert number to host format.
		msg_len = ntohs(msg_len);

		total = 0;

		// Receive whole answer message by parts.
		while (total < msg_len) {
			if (poll(&pfd, 1, 1000 * net->wait) != 1) {
				WARN("response timeout for %s\n",
				     net->remote_str);
				return KNOT_NET_ETIMEOUT;
			}

			// Receive piece of message.
			ret = recv(net->sockfd, buf + total, msg_len - total, 0);
			if (ret <= 0) {
				WARN("can't receive reply from %s\n",
				     net->remote_str);
				return KNOT_NET_ERECV;
			}

			total += ret;
		}

		return total;
	} else {
		struct sockaddr_storage from;
		memset(&from, '\0', sizeof(from));

		// Receive replies unless correct reply or timeout.
		while (true) {
			socklen_t from_len = sizeof(from);

			// Wait for datagram data.
			if (poll(&pfd, 1, 1000 * net->wait) != 1) {
				WARN("response timeout for %s\n",
				     net->remote_str);
				return KNOT_NET_ETIMEOUT;
			}

			// Receive whole UDP datagram.
			ret = recvfrom(net->sockfd, buf, buf_len, 0,
				       (struct sockaddr *)&from, &from_len);
			if (ret <= 0) {
				WARN("can't receive reply from %s\n",
				     net->remote_str);
				return KNOT_NET_ERECV;
			}

			// Compare reply address with the remote one.
			if (from_len > sizeof(from) ||
			    memcmp(&from, net->srv->ai_addr, from_len) != 0) {
				char *src = NULL;
				get_addr_str(&from, net->socktype, &src);
				WARN("unexpected reply source %s\n", src);
				free(src);
				continue;
			}

			return ret;
		}
	}

	return KNOT_NET_ERECV;
}

void net_close(net_t *net)
{
	if (net == NULL) {
		DBG_NULL;
		return;
	}

	close(net->sockfd);
	net->sockfd = -1;
}

void net_clean(net_t *net)
{
	if (net == NULL) {
		DBG_NULL;
		return;
	}

	free(net->local_str);
	free(net->remote_str);

	if (net->local_info != NULL) {
		freeaddrinfo(net->local_info);
	}

	if (net->remote_info != NULL) {
		freeaddrinfo(net->remote_info);
	}
}
