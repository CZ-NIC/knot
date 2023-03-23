/*
 * Copyright © 2005-2020 Rich Felker, et al.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "contrib/musl/inet_ntop.h"
#include "contrib/openbsd/strlcpy.h"

const char *knot_inet_ntop(int af, const void *restrict a0, char *restrict s, socklen_t l)
{
	const unsigned char *a = a0;
	int i, j, max, best;
	char buf[100];

	switch (af) {
	case AF_INET:
		if (snprintf(s, l, "%d.%d.%d.%d", a[0],a[1],a[2],a[3]) < l)
			return s;
		break;
	case AF_INET6:
		if (memcmp(a, "\0\0\0\0\0\0\0\0\0\0\377\377", 12))
			(void)snprintf(buf, sizeof buf,
			               "%x:%x:%x:%x:%x:%x:%x:%x",
			               256*a[0]+a[1],256*a[2]+a[3],
			               256*a[4]+a[5],256*a[6]+a[7],
			               256*a[8]+a[9],256*a[10]+a[11],
			               256*a[12]+a[13],256*a[14]+a[15]);
		else
			(void)snprintf(buf, sizeof buf,
			               "%x:%x:%x:%x:%x:%x:%d.%d.%d.%d",
			               256*a[0]+a[1],256*a[2]+a[3],
			               256*a[4]+a[5],256*a[6]+a[7],
			               256*a[8]+a[9],256*a[10]+a[11],
			               a[12],a[13],a[14],a[15]);
		/* Replace longest /(^0|:)[:0]{2,}/ with "::" */
		for (i=best=0, max=2; buf[i]; i++) {
			if (i && buf[i] != ':') continue;
			j = strspn(buf+i, ":0");
			if (j>max) best=i, max=j;
		}
		if (max>3) {
			buf[best] = buf[best+1] = ':';
			memmove(buf+best+2, buf+best+max, i-best-max+1);
		}
		if (strlen(buf) < l) {
			strlcpy(s, buf, l);
			return s;
		}
		break;
	default:
		errno = EAFNOSUPPORT;
		return 0;
	}
	errno = ENOSPC;
	return 0;
}
