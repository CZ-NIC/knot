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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

#include "libknot/consts.h"
#include "libknot/errcode.h"
#include "contrib/sockaddr.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/macros.h"

int sockaddr_len(const struct sockaddr *sa)
{
	if (sa == NULL) {
		return 0;
	}

	switch(sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	case AF_UNIX:
		return sizeof(struct sockaddr_un);
	default:
		return 0;
	}
}

static int cmp_ipv4(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
	if (a->sin_addr.s_addr < b->sin_addr.s_addr) {
		return -1;
	} else if (a->sin_addr.s_addr > b->sin_addr.s_addr) {
		return 1;
	} else {
		return a->sin_port - b->sin_port;
	}
}

static int cmp_ipv6(const struct sockaddr_in6 *a, const struct sockaddr_in6 *b)
{
	int ret = memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(struct in6_addr));
	if (ret == 0) {
		ret = a->sin6_port - b->sin6_port;
	}

	return ret;
}

static int cmp_unix(const struct sockaddr_un *a, const struct sockaddr_un *b)
{
	int len_a = strnlen(a->sun_path, sizeof(a->sun_path));
	int len_b = strnlen(b->sun_path, sizeof(b->sun_path));
	int len_min = len_a <= len_b ? len_a : len_b;

	int ret = strncmp(a->sun_path, b->sun_path, len_min);
	if (ret == 0) {
		ret = len_a - len_b;
	}

	return ret;
}

int sockaddr_cmp(const struct sockaddr *a, const struct sockaddr *b)
{
	if (a->sa_family != b->sa_family) {
		return (int)a->sa_family - (int)b->sa_family;
	}

	switch (a->sa_family) {
	case AF_UNSPEC:
		return 0;
	case AF_INET:
		return cmp_ipv4((struct sockaddr_in *)a, (struct sockaddr_in *)b);
	case AF_INET6:
		return cmp_ipv6((struct sockaddr_in6 *)a, (struct sockaddr_in6 *)b);
	case AF_UNIX:
		return cmp_unix((struct sockaddr_un *)a, (struct sockaddr_un *)b);
	default:
		return 1;
	}
}

int sockaddr_set(struct sockaddr_storage *ss, int family, const char *straddr, int port)
{
	if (ss == NULL || straddr == NULL) {
		return KNOT_EINVAL;
	}

	/* Set family and port. */
	memset(ss, 0, sizeof(*ss));
	ss->ss_family = family;
	sockaddr_port_set((struct sockaddr *)ss, port);

	/* Initialize address depending on address family. */
	if (family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)ss;
		if (inet_pton(family, straddr, &ipv6->sin6_addr) < 1) {
			return KNOT_ERROR;
		}
		return KNOT_EOK;
	} else if (family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)ss;
		if (inet_pton(family, straddr, &ipv4->sin_addr) < 1) {
			return KNOT_ERROR;
		}
		return KNOT_EOK;
	} else if (family == AF_UNIX) {
		struct sockaddr_un *un = (struct sockaddr_un *)ss;
		size_t ret = strlcpy(un->sun_path, straddr, sizeof(un->sun_path));
		if (ret >= sizeof(un->sun_path)) {
			return KNOT_ESPACE;
		}
		return KNOT_EOK;
	}

	return KNOT_EINVAL;
}

void *sockaddr_raw(const struct sockaddr *sa, size_t *addr_size)
{
	if (sa == NULL || addr_size == NULL) {
		return NULL;
	}

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)sa;
		*addr_size = sizeof(ipv4->sin_addr);
		return &ipv4->sin_addr;
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)sa;
		*addr_size = sizeof(ipv6->sin6_addr);
		return &ipv6->sin6_addr;
	} else {
		return NULL;
	}
}

int sockaddr_set_raw(struct sockaddr_storage *ss, int family,
                     const uint8_t *raw_addr, size_t raw_addr_size)
{
	if (ss == NULL || raw_addr == NULL) {
		return KNOT_EINVAL;
	}

	memset(ss, 0, sizeof(*ss));
	ss->ss_family = family;

	size_t sa_size = 0;
	void *sa_data = sockaddr_raw((struct sockaddr *)ss, &sa_size);
	if (sa_data == NULL || sa_size != raw_addr_size) {
		return KNOT_EINVAL;
	}

	memcpy(sa_data, raw_addr, sa_size);

	return KNOT_EOK;
}

int sockaddr_tostr(char *buf, size_t maxlen, const struct sockaddr *sa)
{
	if (sa == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	const char *out = NULL;

	/* Convert network address string. */
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
		out = inet_ntop(sa->sa_family, &s->sin6_addr, buf, maxlen);
	} else if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *s = (const struct sockaddr_in *)sa;
		out = inet_ntop(sa->sa_family, &s->sin_addr, buf, maxlen);
	} else if (sa->sa_family == AF_UNIX) {
		const struct sockaddr_un *s = (const struct sockaddr_un *)sa;
		size_t ret = strlcpy(buf, s->sun_path, maxlen);
		out = (ret < maxlen) ? buf : NULL;
	} else {
		return KNOT_EINVAL;
	}

	if (out == NULL) {
		*buf = '\0';
		return KNOT_ESPACE;
	}

	/* Write separator and port. */
	int written = strlen(buf);
	int port = sockaddr_port(sa);
	if (port > 0) {
		int ret = snprintf(&buf[written], maxlen - written, "@%d", port);
		if (ret <= 0 || (size_t)ret >= maxlen - written) {
			*buf = '\0';
			return KNOT_ESPACE;
		}

		written += ret;
	}

	return written;
}

int sockaddr_port(const struct sockaddr *sa)
{
	if (sa == NULL) {
		return KNOT_EINVAL;
	}

	if (sa->sa_family == AF_INET6) {
		return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
	} else if (sa->sa_family == AF_INET) {
		return ntohs(((struct sockaddr_in *)sa)->sin_port);
	} else {
		return KNOT_EINVAL;
	}
}

void sockaddr_port_set(struct sockaddr *sa, uint16_t port)
{
	if (sa == NULL) {
		return;
	}

	if (sa->sa_family == AF_INET6) {
		((struct sockaddr_in6 *)sa)->sin6_port = htons(port);
	} else if (sa->sa_family == AF_INET) {
		((struct sockaddr_in *)sa)->sin_port = htons(port);
	}
}

char *sockaddr_hostname(void)
{
	/* Fetch hostname. */
	char host[KNOT_DNAME_MAXLEN + 1] = { '\0' };
	if (gethostname(host, sizeof(host)) != 0) {
		return NULL;
	}
	/* Just to be sure. */
	host[sizeof(host) - 1] = '\0';

	/* Fetch canonical name for this address/DNS. */
	struct addrinfo hints, *info = NULL;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_CANONNAME;
	if (getaddrinfo(host, "domain", &hints, &info) != 0) {
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

bool sockaddr_is_any(const struct sockaddr *sa)
{
	if (sa == NULL) {
		return false;
	}

	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *ipv4 = (struct sockaddr_in *)sa;
		return ipv4->sin_addr.s_addr == INADDR_ANY;
	}

	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)sa;
		return memcmp(&ipv6->sin6_addr, &in6addr_any, sizeof(ipv6->sin6_addr)) == 0;
	}

	return false;
}

bool sockaddr_net_match(const struct sockaddr *ss1,
                        const struct sockaddr *ss2,
                        unsigned prefix)
{
	if (ss1 == NULL || ss2 == NULL) {
		return false;
	}

	if (ss1->sa_family != ss2->sa_family) {
		return false;
	}

	size_t raw_len = 0;
	const uint8_t *raw_1 = sockaddr_raw(ss1, &raw_len);
	const uint8_t *raw_2 = sockaddr_raw(ss2, &raw_len);

	prefix = MIN(prefix, raw_len * 8);
	unsigned bytes = prefix / 8;
	unsigned bits = prefix % 8;

	/* Compare full bytes. */
	if (memcmp(raw_1, raw_2, bytes) != 0) {
		return false;
	}

	/* Compare last partial byte. */
	return bits == 0 ||
	       (raw_1[bytes] >> (8 - bits) == raw_2[bytes] >> (8 - bits));
}

bool sockaddr_range_match(const struct sockaddr *sa,
                          const struct sockaddr *ss_min,
                          const struct sockaddr *ss_max)
{
	if (sa == NULL || ss_min == NULL || ss_max == NULL) {
		return false;
	}

	if (ss_min->sa_family != ss_max->sa_family ||
	    ss_min->sa_family != sa->sa_family) {
		return false;
	}

	return sockaddr_cmp(sa, ss_min) >= 0 && sockaddr_cmp(sa, ss_max) <= 0;
}
