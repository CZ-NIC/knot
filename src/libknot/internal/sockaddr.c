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
#include <netdb.h>

#include "libknot/consts.h"
#include "libknot/internal/macros.h"
#include "libknot/internal/utils.h"
#include "libknot/internal/sockaddr.h"
#include "libknot/internal/errcode.h"
#include "contrib/openbsd/strlcpy.h"

int sockaddr_len(const struct sockaddr *ss)
{
	if (ss == NULL) {
		return 0;
	}

	const struct sockaddr_storage *sa = (const struct sockaddr_storage *)ss;
	switch(sa->ss_family) {
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

int sockaddr_cmp(const struct sockaddr_storage *k1, const struct sockaddr_storage *k2)
{
	if (k1->ss_family != k2->ss_family) {
		return (int)k1->ss_family - (int)k2->ss_family;
	}

	return memcmp(k1, k2, sockaddr_len((const struct sockaddr *)k1));
}

int sockaddr_set(struct sockaddr_storage *ss, int family, const char *straddr, int port)
{
	if (ss == NULL || straddr == NULL) {
		return KNOT_EINVAL;
	}

	/* Clear the structure and set family and port. */
	memset(ss, 0, sizeof(struct sockaddr_storage));
	ss->ss_family = family;
	sockaddr_port_set(ss, port);

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

void *sockaddr_raw(struct sockaddr_storage *ss, size_t *addr_size)
{
	if (ss == NULL || addr_size == NULL) {
		return NULL;
	}

	if (ss->ss_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)ss;
		*addr_size = sizeof(ipv4->sin_addr);
		return &ipv4->sin_addr;
	} else if (ss->ss_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)ss;
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

	ss->ss_family = family;

	size_t sa_size = 0;
	void *sa_data = sockaddr_raw(ss, &sa_size);

	if (sa_data == NULL || sa_size != raw_addr_size) {
		return KNOT_EINVAL;
	}

	memset(ss, 0, sizeof(*ss));
	ss->ss_family = family;
	memcpy(sa_data, raw_addr, sa_size);

	return KNOT_EOK;
}

int sockaddr_tostr(char *buf, size_t maxlen, const struct sockaddr_storage *ss)
{
	if (ss == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	const char *out = NULL;

	/* Convert network address string. */
	if (ss->ss_family == AF_INET6) {
		const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)ss;
		out = inet_ntop(ss->ss_family, &s->sin6_addr, buf, maxlen);
	} else if (ss->ss_family == AF_INET) {
		const struct sockaddr_in *s = (const struct sockaddr_in *)ss;
		out = inet_ntop(ss->ss_family, &s->sin_addr, buf, maxlen);
	} else if (ss->ss_family == AF_UNIX) {
		const struct sockaddr_un *s = (const struct sockaddr_un *)ss;
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
	int port = sockaddr_port(ss);
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

int sockaddr_port(const struct sockaddr_storage *ss)
{
	if (ss == NULL) {
		return KNOT_EINVAL;
	}

	if (ss->ss_family == AF_INET6) {
		return ntohs(((struct sockaddr_in6 *)ss)->sin6_port);
	} else if (ss->ss_family == AF_INET) {
		return ntohs(((struct sockaddr_in *)ss)->sin_port);
	} else {
		return KNOT_EINVAL;
	}
}

void sockaddr_port_set(struct sockaddr_storage *ss, uint16_t port)
{
	if (ss == NULL) {
		return;
	}

	if (ss->ss_family == AF_INET6) {
		((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
	} else if (ss->ss_family == AF_INET) {
		((struct sockaddr_in *)ss)->sin_port = htons(port);
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
