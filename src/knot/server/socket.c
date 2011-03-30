#include <config.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "knot/common.h"
#include "knot/server/socket.h"

int socket_create(int family, int type)
{
	/* Create socket. */
	return socket(family, type, 0);
}

int socket_connect(int fd, const char *addr, unsigned short port)
{
	/* NULL address => any */
	if (!addr) {
		addr = "0.0.0.0";
	}

	/* Resolve address. */
	int ret = 0;
	struct addrinfo hints, *res;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((ret = getaddrinfo(addr, NULL, &hints, &res)) != 0) {
		return -1;
	}

	/* Evaluate address type. */
	struct sockaddr *saddr = 0;
	socklen_t addrlen = 0;
#ifndef DISABLE_IPV6
	if (res->ai_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)res->ai_addr;
		ipv6->sin6_port = htons(port);
		saddr = (struct sockaddr*)ipv6;
		addrlen = sizeof(struct sockaddr_in6);
	}
#endif
	if (res->ai_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in*)res->ai_addr;
		ipv4->sin_port = htons(port);
		saddr = (struct sockaddr*)ipv4;
		addrlen = sizeof(struct sockaddr_in);
	}

	/* Connect. */
	ret = -1;
	if (addr) {
		ret = connect(fd, saddr, addrlen);
	}

	/* Free addresses. */
	freeaddrinfo(res);

	return ret;
}

int socket_bind(int socket, int family, const char *addr, unsigned short port)
{
	/* Check address family. */
	struct sockaddr* paddr = 0;
	socklen_t addrlen = 0;
	struct sockaddr_in saddr;
#ifndef DISABLE_IPV6
	struct sockaddr_in6 saddr6;
#endif
	if (family == AF_INET) {

		/* Initialize socket address. */
		paddr = (struct sockaddr*)&saddr;
		addrlen = sizeof(saddr);
		if (getsockname(socket, paddr, &addrlen) < 0) {
			return -1;
		}

		/* Set address and port. */
		saddr.sin_port = htons(port);
		if (inet_pton(family, addr, &saddr.sin_addr) < 0) {
			saddr.sin_addr.s_addr = INADDR_ANY;
			char buf[INET_ADDRSTRLEN];
			inet_ntop(family, &saddr.sin_addr, buf, sizeof(buf));
			log_server_error("sockets: Address '%s' is invalid, "
			                 "using '%s' instead.\n",
			                 addr, buf);

		}

	} else {

#ifdef DISABLE_IPV6
		log_error("sockets: ipv6 support disabled\n");
		return -1;
#else
		/* Initialize socket address. */
		paddr = (struct sockaddr*)&saddr6;
		addrlen = sizeof(saddr6);
		if (getsockname(socket, paddr, &addrlen) < 0) {
			return -1;
		}

		/* Set address and port. */
		saddr6.sin6_port = htons(port);
		if (inet_pton(family, addr, &saddr6.sin6_addr) < 0) {
			memcpy(&saddr6.sin6_addr, &in6addr_any, sizeof(in6addr_any));
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(family, &saddr6.sin6_addr, buf, sizeof(buf));
			log_server_error("sockets: Address '%s' is invalid, "
			                 "using '%s' instead\n",
			                 addr, buf);

		}
#endif
	}

	/* Reuse old address if taken. */
	int flag = 1;
	int ret = setsockopt(socket, SOL_SOCKET, SO_REUSEADDR,
	                     &flag, sizeof(flag));
	if (ret < 0) {
		return -2;
	}

	/* Bind to specified address. */
	int res = bind(socket, paddr, addrlen);
	if (res < 0) {
		log_server_error("%s: cannot bind socket (errno %d): %s.\n",
		                 __func__, errno, strerror(errno));
		return -3;
	}

	return 0;
}

int socket_listen(int socket, int backlog_size)
{
	return listen(socket, backlog_size);
}

int socket_close(int socket)
{
	return close(socket);
}

