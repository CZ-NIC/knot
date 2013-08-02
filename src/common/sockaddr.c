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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "common/sockaddr.h"
#include "libknot/consts.h"

int sockaddr_init(sockaddr_t *addr, int af)
{
	/* Reset pointer. */
	memset(addr, 0, sizeof(sockaddr_t));

	/* Initialize address size. */
	switch(af) {
	case AF_INET:
		addr->len = sizeof(struct sockaddr_in);
		addr->prefix = IPV4_PREFIXLEN;
		break;
#ifndef DISABLE_IPV6
	case AF_INET6:
		addr->len = sizeof(struct sockaddr_in6);
		addr->prefix = IPV6_PREFIXLEN;
		break;
#endif
	default:
		return -1;
	}

	return 0;
}

int sockaddr_isvalid(sockaddr_t *addr)
{
	return addr && (addr->len > 0);
}

int sockaddr_copy(sockaddr_t *dst, const sockaddr_t *src)
{
	if (memcpy(dst, src, sizeof(sockaddr_t)) != NULL) {
		return 0;
	}

	return -1;
}

int sockaddr_set(sockaddr_t *dst, int family, const char* addr, int port)
{
	if (!dst || !addr || port < 0) {
		return -1;
	}

	/* Initialize. */
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
		dst->prefix = IPV4_PREFIXLEN;
		break;
#ifndef DISABLE_IPV6
	case AF_INET6:
		dst->addr6.sin6_family = family;
		dst->addr6.sin6_port = htons(port);
		paddr = &dst->addr6.sin6_addr;
		memcpy(&dst->addr6.sin6_addr,
		       &in6addr_any, sizeof(in6addr_any));
		dst->prefix = IPV6_PREFIXLEN;
		break;
#endif
	default:
		return -1;
	}

	/* Convert address. */
	return inet_pton(family, addr, paddr);
}

int sockaddr_setprefix(sockaddr_t *dst, int prefix)
{
	if (dst == NULL || prefix < 0) {
		return -1;
	}

	return dst->prefix = prefix;
}

int sockaddr_tostr(const sockaddr_t *addr, char *dst, size_t size)
{
	if (!addr || !dst || size == 0) {
		return -1;
	}

	/* Minimum length. */
	size_t minlen = INET_ADDRSTRLEN;

	/* Check unsupported IPv6. */
#ifndef DISABLE_IPV6
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
	if (addr->len == sizeof(struct sockaddr_in6)) {
		inet_ntop(AF_INET6, &addr->addr6.sin6_addr, dst, size);
	}
#endif
	/* Load IPv4 if set. */
	if (addr->len == sizeof(struct sockaddr_in)) {
		inet_ntop(AF_INET, &addr->addr4.sin_addr, dst, size);
	}

	return 0;
}

int sockaddr_portnum(const sockaddr_t *addr)
{
	if (!addr) {
		return -1;
	}

	switch(addr->len) {

	/* IPv4 */
	case sizeof(struct sockaddr_in):
		return ntohs(addr->addr4.sin_port);
		break;

	/* IPv6 */
#ifndef DISABLE_IPV6
	case sizeof(struct sockaddr_in6):
		return ntohs(addr->addr6.sin6_port);
		break;
#endif

	/* N/A */
	default:
		return -1;
		break;
	}
}

int sockaddr_family(const sockaddr_t *addr)
{
	switch(addr->len) {
	case sizeof(struct sockaddr_in):  return AF_INET; break;
#ifndef DISABLE_IPV6
	case sizeof(struct sockaddr_in6): return AF_INET6; break;
#endif
	default: return 0; break;
	}
}

void sockaddr_prep(sockaddr_t *addr)
{
#ifndef DISABLE_IPV6
	addr->len = sizeof(struct sockaddr_in6);
#else
	addr->len = sizeof(struct sockaddr_in);
#endif
}

char *sockaddr_hostname(void)
{
	/* Fetch hostname. */
	char host[KNOT_MAX_DNAME_LENGTH];
	if (gethostname(host, KNOT_MAX_DNAME_LENGTH) != 0) {
		return NULL;
	}

	/* Fetch canonical name for this address/DNS. */
	int ret = 0;
	struct addrinfo hints, *info;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_CANONNAME;
	if ((ret = getaddrinfo(host, "domain", &hints, &info)) != 0) {
		return NULL;
	}

	/* Fetch first valid hostname. */
	char *hname = NULL;
	struct addrinfo *p = NULL;
	for (p = info; p != NULL; p = p->ai_next) {
		if (p->ai_canonname) {
			hname = strdup(p->ai_canonname);
			break;
		}
	}

	/* No valid hostname found, resort to gethostname() result */
	if (hname == NULL) {
		hname = strdup(host);
	}

	freeaddrinfo(info);
	return hname;
}
