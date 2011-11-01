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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "common/sockaddr.h"

int sockaddr_init(sockaddr_t *addr, int af)
{
	/* Reset pointer. */
	memset(addr, 0, sizeof(sockaddr_t));
	addr->family = -1;

	/* Initialize address size. */
	switch(af) {
	case AF_INET:
		addr->len = sizeof(struct sockaddr_in);
		break;
#ifndef DISABLE_IPV6
	case AF_INET6:
		addr->len = sizeof(struct sockaddr_in6);
		break;
#endif
	default:
		return -1;
	}

	/* Update pointer. */
	addr->family = af;
	return sockaddr_update(addr);
}

int sockaddr_update(sockaddr_t *addr)
{
	/* Update internal pointer. */
	switch(addr->len) {
	case sizeof(struct sockaddr_in):
		addr->ptr = (struct sockaddr*)&addr->addr4;
		break;
#ifndef DISABLE_IPV6
	case sizeof(struct sockaddr_in6):
		addr->ptr = (struct sockaddr*)&addr->addr6;
		break;
#endif
	default:
		return -1;
	}

	return 0;
}

int sockaddr_set(sockaddr_t *dst, int family, const char* addr, int port)
{
	if (!dst || !addr || port < 0) {
		return -1;
	}

	/* Initialize. */
	dst->family = -1;
	dst->ptr = 0;
	dst->len = 0;
	sockaddr_init(dst, family);

	/* Initialize depending on address family. */
	void *paddr = 0;
	switch(family) {
	case AF_INET:
		dst->addr4.sin_family = family;
		dst->addr4.sin_port = htons(port);
		paddr = &dst->addr4.sin_addr;
		dst->addr4.sin_addr.s_addr = INADDR_ANY;
		break;
#ifndef DISABLE_IPV6
	case AF_INET6:
		dst->addr6.sin6_family = family;
		dst->addr6.sin6_port = htons(port);
		paddr = &dst->addr6.sin6_addr;
		memcpy(&dst->addr6.sin6_addr,
		       &in6addr_any, sizeof(in6addr_any));
		break;
#endif
	default:
		return -1;
	}

	/* Convert address. */
	return inet_pton(family, addr, paddr);
}

int sockaddr_tostr(sockaddr_t *addr, char *dst, size_t size)
{
	if (!addr || !dst || size == 0) {
		return -1;
	}

	/* Minimum length. */
	size_t minlen = INET_ADDRSTRLEN;

	/* Check unsupported IPv6. */
#ifdef DISABLE_IPV6
	if (addr->family == AF_INET6) {
		return -1;
	}
#else
	minlen = INET6_ADDRSTRLEN;
#endif

	/* Check minimum length. */
	if (size < minlen) {
		return -1;
	}

	/* Convert. */
#ifdef DISABLE_IPV6
	dst[0] = '\0';
#else
	/* Load IPv6 addr if default. */
	if (addr->family == AF_INET6) {
		inet_ntop(addr->family, &addr->addr6.sin6_addr,
			  dst, size);
	}
#endif
	/* Load IPv4 if set. */
	if (addr->family == AF_INET) {
		inet_ntop(addr->family, &addr->addr4.sin_addr,
			  dst, size);
	}

	return 0;
}

int sockaddr_portnum(sockaddr_t *addr)
{
	if (!addr) {
		return -1;
	}

	switch(addr->family) {

	/* IPv4 */
	case AF_INET:
		return ntohs(addr->addr4.sin_port);
		break;

	/* IPv6 */
#ifndef DISABLE_IPV6
	case AF_INET6:
		return ntohs(addr->addr6.sin6_port);
		break;
#endif

	/* N/A */
	default:
		return -1;
		break;
	}
}
