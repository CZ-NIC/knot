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

// FreeBSD POSIX2008 getline
#ifndef _WITH_GETLINE
 #define _WITH_GETLINE
#endif

#include "common/getline_wrap.h"
#include "config.h"		// HAVE_

#include <stdio.h>		// getline or fgetln
#include <stdlib.h>		// free
#include <string.h>		// memcpy

char* getline_wrap(FILE *stream, size_t *len)
{
	char *buf = NULL;

#ifdef HAVE_GETLINE
	ssize_t size = getline(&buf, len, stream);

	if (size <= 0) {
		return NULL;
	}

	*len = size;

	return buf;
#elif HAVE_FGETLN
	buf = fgetln(stream, len);

	if (buf == NULL) {
		return NULL;
	}

	if (buf[*len - 1] == '\n') {
		buf[*len - 1] = '\0';
	} else {
		char *lbuf = NULL;

		if ((lbuf = (char *)malloc(*len + 1)) == NULL) {
			free(buf);
			return NULL;
		}

		memcpy(lbuf, buf, *len);
		lbuf[*len] = '\0';
		free(buf);
		buf = lbuf;
	}

	return buf;
#else
#error Missing getline or fgetln function
#endif
}

ssize_t knot_getline(char **lineptr, size_t *n, FILE *stream)
{
#ifdef HAVE_GETLINE
	return getline(lineptr, n, stream);
#elif HAVE_FGETLN
	size_t length = 0;
	char *buffer = fgetln(stream, *length);
	if (data == NULL)
		return -1;

	if (*lineptr)
		free(*lineptr);

	*lineptr = buffer;
	*n = length;

	return length;
#endif
}
