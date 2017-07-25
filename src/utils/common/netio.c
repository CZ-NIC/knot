/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include "utils/common/netio.h"
#include "utils/common/msg.h"
#include "utils/common/tls.h"
#include "libknot/libknot.h"
#include "contrib/sockaddr.h"

srv_info_t *srv_info_create(const char *name, const char *service)
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

const char *get_sockname(const int socktype)
{
	switch (socktype) {
	case SOCK_STREAM:
		return "TCP";
	case SOCK_DGRAM:
		return "UDP";
	default:
		return "UNKNOWN";
	}
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
		ERR("can't resolve address %s@%s\n",
		    server->name, server->service);
		return -1;
	}

	return 0;
}

void get_addr_str(const struct sockaddr_storage *ss,
                  const int                     socktype,
                  char                          **dst)
{
	char addr_str[SOCKADDR_STRLEN] = {0};

	// Get network address string and port number.
	sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr *)ss);

	// Calculate needed buffer size
	const char *sock_name = get_sockname(socktype);
	size_t buflen = strlen(addr_str) + strlen(sock_name) + 3 /* () */;

	// Free previous string if any and write result
	free(*dst);
	*dst = malloc(buflen);
	if (*dst != NULL) {
		int ret = snprintf(*dst, buflen, "%s(%s)", addr_str, sock_name);
		if (ret <= 0 || ret >= buflen) {
			**dst = '\0';
		}
	}
}

int net_init(const srv_info_t    *local,
             const srv_info_t    *remote,
             const int           iptype,
             const int           socktype,
             const int           wait,
             const net_flags_t   flags,
             const tls_params_t  *tls_params,
             net_t               *net)
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
	net->flags = flags;

	// Prepare for TLS.
	if (tls_params != NULL && tls_params->enable) {
		int ret = tls_ctx_init(&net->tls, tls_params, net->wait);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/**
 * Connect with TCP Fast Open.
 */
static int fastopen_connect(int sockfd, const struct addrinfo *srv)
{
#if __APPLE__
	// connection is performed lazily when first data are sent
	struct sa_endpoints ep = {0};
	ep.sae_dstaddr = srv->ai_addr;
	ep.sae_dstaddrlen = srv->ai_addrlen;
	int flags =  CONNECT_DATA_IDEMPOTENT|CONNECT_RESUME_ON_READ_WRITE;

	return connectx(sockfd, &ep, SAE_ASSOCID_ANY, flags, NULL, 0, NULL, NULL);
#elif defined(MSG_FASTOPEN) // Linux with RFC 7413
	// connect() will be called implicitly with sendto(), sendmsg()
	return 0;
#else
	errno = ENOTSUP;
	return -1;
#endif
}

/**
 * Sends data with TCP Fast Open.
 */
static int fastopen_send(int sockfd, const struct msghdr *msg, int timeout)
{
#if __APPLE__
	return sendmsg(sockfd, msg, 0);
#elif defined(MSG_FASTOPEN)
	int ret = sendmsg(sockfd, msg, MSG_FASTOPEN);
	if (ret == -1 && errno == EINPROGRESS) {
		struct pollfd pfd = {
			.fd = sockfd,
			.events = POLLOUT,
			.revents = 0,
		};
		if (poll(&pfd, 1, 1000 * timeout) != 1) {
			errno = ETIMEDOUT;
			return -1;
		}
		ret = sendmsg(sockfd, msg, 0);
	}
	return ret;
#else
	errno = ENOTSUP;
	return -1;
#endif
}

int net_connect(net_t *net)
{
	if (net == NULL || net->srv == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Set remote information string.
	get_addr_str((struct sockaddr_storage *)net->srv->ai_addr,
	             net->socktype, &net->remote_str);

	// Create socket.
	int sockfd = socket(net->srv->ai_family, net->socktype, 0);
	if (sockfd == -1) {
		WARN("can't create socket for %s\n", net->remote_str);
		return KNOT_NET_ESOCKET;
	}

	// Initialize poll descriptor structure.
	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLOUT,
		.revents = 0,
	};

	// Set non-blocking socket.
	if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
		WARN("can't set non-blocking socket for %s\n", net->remote_str);
		return KNOT_NET_ESOCKET;
	}

	// Bind address to socket if specified.
	if (net->local_info != NULL) {
		if (bind(sockfd, net->local_info->ai_addr,
		         net->local_info->ai_addrlen) == -1) {
			WARN("can't assign address %s\n", net->local->name);
			return KNOT_NET_ESOCKET;
		}
	}

	if (net->socktype == SOCK_STREAM) {
		int  cs, err, ret = 0;
		socklen_t err_len = sizeof(err);
		bool     fastopen = net->flags & NET_FLAGS_FASTOPEN;

		// Connect using socket.
		if (fastopen) {
			ret = fastopen_connect(sockfd, net->srv);
		} else {
			ret = connect(sockfd, net->srv->ai_addr, net->srv->ai_addrlen);
		}
		if (ret != 0 && errno != EINPROGRESS) {
			WARN("can't connect to %s\n", net->remote_str);
			close(sockfd);
			return KNOT_NET_ECONNECT;
		}

		// Check for connection timeout.
		if (!fastopen && poll(&pfd, 1, 1000 * net->wait) != 1) {
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

		// Establish TLS connection.
		if (net->tls.params != NULL) {
			int ret = tls_ctx_connect(&net->tls, sockfd, net->remote->name);
			if (ret != KNOT_EOK) {
				close(sockfd);
				return ret;
			}
		}
	}

	// Store socket descriptor.
	net->sockfd = sockfd;

	return KNOT_EOK;
}

int net_set_local_info(net_t *net)
{
	if (net == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	if (net->local_info != NULL) {
		freeaddrinfo(net->local_info);
	}

	socklen_t local_addr_len = sizeof(struct sockaddr_storage);
	struct sockaddr_storage *local_addr = calloc(1, local_addr_len);

	if (getsockname(net->sockfd, (struct sockaddr *)local_addr,
	                &local_addr_len) == -1) {
		WARN("can't get local address\n");
		free(local_addr);
		return KNOT_NET_ESOCKET;
	}

	net->local_info = calloc(1, sizeof(struct addrinfo));
	net->local_info->ai_family = net->srv->ai_family;
	net->local_info->ai_socktype = net->srv->ai_socktype;
	net->local_info->ai_protocol = net->srv->ai_protocol;
	net->local_info->ai_addrlen = local_addr_len;
	net->local_info->ai_addr = (struct sockaddr *)local_addr;

	get_addr_str((struct sockaddr_storage *)net->local_info->ai_addr,
	             net->socktype, &net->local_str);

	return KNOT_EOK;
}

int net_send(const net_t *net, const uint8_t *buf, const size_t buf_len)
{
	if (net == NULL || buf == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Send data over UDP.
	if (net->socktype == SOCK_DGRAM) {
		if (sendto(net->sockfd, buf, buf_len, 0, net->srv->ai_addr,
		           net->srv->ai_addrlen) != (ssize_t)buf_len) {
			WARN("can't send query to %s\n", net->remote_str);
			return KNOT_NET_ESEND;
		}
	// Send data over TLS.
	} else if (net->tls.params != NULL) {
		int ret = tls_ctx_send((tls_ctx_t *)&net->tls, buf, buf_len);
		if (ret != KNOT_EOK) {
			WARN("can't send query to %s\n", net->remote_str);
			return KNOT_NET_ESEND;
		}
	// Send data over TCP.
	} else {
		bool fastopen = net->flags & NET_FLAGS_FASTOPEN;

		// Leading packet length bytes.
		uint16_t pktsize = htons(buf_len);

		struct iovec iov[2];
		iov[0].iov_base = &pktsize;
		iov[0].iov_len = sizeof(pktsize);
		iov[1].iov_base = (uint8_t *)buf;
		iov[1].iov_len = buf_len;

		// Compute packet total length.
		ssize_t total = iov[0].iov_len + iov[1].iov_len;

		struct msghdr msg = {0};
		msg.msg_iov = iov;
		msg.msg_iovlen = sizeof(iov) / sizeof(*iov);
		msg.msg_name = net->srv->ai_addr;
		msg.msg_namelen = net->srv->ai_addrlen;

		int ret = 0;
		if (fastopen) {
			ret = fastopen_send(net->sockfd, &msg, net->wait);
		} else {
			ret = sendmsg(net->sockfd, &msg, 0);
		}
		if (ret != total) {
			WARN("can't send query to %s\n", net->remote_str);
			return KNOT_NET_ESEND;
		}
	}

	return KNOT_EOK;
}

int net_receive(const net_t *net, uint8_t *buf, const size_t buf_len)
{
	if (net == NULL || buf == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Initialize poll descriptor structure.
	struct pollfd pfd = {
		.fd = net->sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	// Receive data over UDP.
	if (net->socktype == SOCK_DGRAM) {
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
			ssize_t ret = recvfrom(net->sockfd, buf, buf_len, 0,
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
	// Receive data over TLS.
	} else if (net->tls.params != NULL) {
		int ret = tls_ctx_receive((tls_ctx_t *)&net->tls, buf, buf_len);
		if (ret < 0) {
			WARN("can't receive reply from %s\n", net->remote_str);
			return KNOT_NET_ERECV;
		}

		return ret;
	// Receive data over TCP.
	} else {
		uint32_t total = 0;

		uint16_t msg_len = 0;
		// Receive TCP message header.
		while (total < sizeof(msg_len)) {
			if (poll(&pfd, 1, 1000 * net->wait) != 1) {
				WARN("response timeout for %s\n",
				     net->remote_str);
				return KNOT_NET_ETIMEOUT;
			}

			// Receive piece of message.
			ssize_t ret = recv(net->sockfd, (uint8_t *)&msg_len + total,
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
		if (msg_len > buf_len) {
			return KNOT_ESPACE;
		}

		total = 0;

		// Receive whole answer message by parts.
		while (total < msg_len) {
			if (poll(&pfd, 1, 1000 * net->wait) != 1) {
				WARN("response timeout for %s\n",
				     net->remote_str);
				return KNOT_NET_ETIMEOUT;
			}

			// Receive piece of message.
			ssize_t ret = recv(net->sockfd, buf + total, msg_len - total, 0);
			if (ret <= 0) {
				WARN("can't receive reply from %s\n",
				     net->remote_str);
				return KNOT_NET_ERECV;
			}
			total += ret;
		}

		return total;
	}

	return KNOT_NET_ERECV;
}

void net_close(net_t *net)
{
	if (net == NULL) {
		DBG_NULL;
		return;
	}

	tls_ctx_close(&net->tls);
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

	tls_ctx_deinit(&net->tls);
}
