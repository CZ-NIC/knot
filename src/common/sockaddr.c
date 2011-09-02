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
	const char *ret = inet_ntop(addr->family, addr->ptr, dst, size);
	if (ret == 0) {
		return -1;
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
		return addr->addr4.sin_port;
		break;

	/* IPv6 */
#ifndef DISABLE_IPV6
	case AF_INET6:
		return addr->addr6.sin6_port;
		break;
#endif

	/* N/A */
	default:
		return -1;
		break;
	}
}
