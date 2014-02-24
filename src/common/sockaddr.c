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
#include <netdb.h>

#include "common/sockaddr.h"
#include "common/errcode.h"
#include "libknot/consts.h"

int sockaddr_len(const struct sockaddr_storage *ss)
{
	switch(ss->ss_family) {
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

	return memcmp(k1, k2, sockaddr_len(k1));
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
		if (strlen(straddr) > sizeof(un->sun_path) - 1) {
			return KNOT_ESPACE;
		}
		strcpy(un->sun_path, straddr);
		return KNOT_EOK;
	}

	return KNOT_EINVAL;
}

int sockaddr_tostr(const struct sockaddr_storage *ss, char *buf, size_t maxlen)
{
	if (ss == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	const char* ret = NULL;

	/* Convert network address string. */
	if (ss->ss_family == AF_INET6) {
		const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)ss;
		ret = inet_ntop(ss->ss_family, &s->sin6_addr, buf, maxlen);
	} else if (ss->ss_family == AF_INET) {
		const struct sockaddr_in *s = (const struct sockaddr_in *)ss;
		ret = inet_ntop(ss->ss_family, &s->sin_addr, buf, maxlen);
	} else if (ss->ss_family == AF_UNIX) {
		const struct sockaddr_un *s = (const struct sockaddr_un *)ss;
		if (strlen(s->sun_path) > maxlen - 1) {
			return KNOT_ESPACE;
		}
		ret = strcpy(buf, s->sun_path);
	} else {
		return KNOT_EINVAL;
	}

	if (ret == NULL) {
		return KNOT_ESPACE;
	}

	/* Write separator and port. */
	int port = sockaddr_port(ss);
	if (port > 0) {
		/* Check available space. */
		size_t written = strlen(buf);
		if (written + SOCKADDR_STRLEN_EXT > maxlen) {
			return KNOT_ESPACE;
		}
		/* Write separator. */
		buf[written] = '@';
		written += 1;
		/* Write port number. */
		sprintf(&buf[written], "%d", port);
	}

	return KNOT_EOK;
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
	char host[KNOT_DNAME_MAXLEN];
	if (gethostname(host, KNOT_DNAME_MAXLEN) != 0) {
		return NULL;
	}

	/* Fetch canonical name for this address/DNS. */
	struct addrinfo hints, *info;
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
