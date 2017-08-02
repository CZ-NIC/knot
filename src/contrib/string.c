/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "contrib/string.h"

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
	char *strp = NULL;
	va_list ap;

	va_start(ap, fmt);
	int ret = vasprintf(&strp, fmt, ap);
	va_end(ap);

	if (ret < 0) {
		return NULL;
	}
	return strp;
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
	while (isspace((int)scan[0])) {
		scan += 1;
	}

	// trailing white-spaces
	size_t len = strlen(scan);
	while (len > 0 && isspace((int)scan[len - 1])) {
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
