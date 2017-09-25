/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "contrib/string.h"
#include "contrib/ctype.h"

uint8_t *memdup(const uint8_t *data, size_t data_size)
{
	uint8_t *result = (uint8_t *)malloc(data_size);
	if (!result) {
		return NULL;
	}

	return memcpy(result, data, data_size);
}

char *sprintf_alloc(const char *fmt, ...)
{
	int size = 100;
	char *p = NULL, *np = NULL;
	va_list ap;

	if ((p = malloc(size)) == NULL)
		return NULL;

	while (1) {

		/* Try to print in the allocated space. */
		va_start(ap, fmt);
		int n = vsnprintf(p, size, fmt, ap);
		va_end(ap);

		/* If that worked, return the string. */
		if (n > -1 && n < size)
			return p;

		/* Else try again with more space. */
		if (n > -1) {       /* glibc 2.1 */
			size = n+1; /* precisely what is needed */
		} else {            /* glibc 2.0 */
			size *= 2;  /* twice the old size */
		}
		if ((np = realloc (p, size)) == NULL) {
			free(p);
			return NULL;
		} else {
			p = np;
		}
	}

	/* Should never get here. */
	return p;
}

char *strcdup(const char *s1, const char *s2)
{
	if (!s1 || !s2) {
		return NULL;
	}

	size_t s1len = strlen(s1);
	size_t s2len = strlen(s2);
	size_t nlen = s1len + s2len + 1;

	char* dst = malloc(nlen);
	if (dst == NULL) {
		return NULL;
	}

	memcpy(dst, s1, s1len);
	memcpy(dst + s1len, s2, s2len + 1);
	return dst;
}

char *strstrip(const char *str)
{
	// leading white-spaces
	const char *scan = str;
	while (is_space(scan[0])) {
		scan += 1;
	}

	// trailing white-spaces
	size_t len = strlen(scan);
	while (len > 0 && is_space(scan[len - 1])) {
		len -= 1;
	}

	char *trimmed = malloc(len + 1);
	if (!trimmed) {
		return NULL;
	}

	memcpy(trimmed, scan, len);
	trimmed[len] = '\0';

	return trimmed;
}

int const_time_memcmp(const void *s1, const void *s2, size_t n)
{
	volatile uint8_t equal = 0;

	for (size_t i = 0; i < n; i++) {
		equal |= ((uint8_t *)s1)[i] ^ ((uint8_t *)s2)[i];
	}

	return equal;
}
