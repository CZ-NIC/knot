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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// FreeBSD POSIX2008 getline
#ifndef _WITH_GETLINE
#define _WITH_GETLINE
#endif

#include "contrib/getline.h"

#include <stdio.h>		// getline or fgetln
#include <stdlib.h>		// free
#include <string.h>		// memcpy

ssize_t knot_getline(char **lineptr, size_t *n, FILE *stream)
{
#ifdef HAVE_GETLINE
	return getline(lineptr, n, stream);
#else
#ifdef HAVE_FGETLN
	size_t length = 0;
	char *buffer = fgetln(stream, &length);
	if (buffer == NULL) {
		return -1;
	}

	/* NOTE: Function fgetln doesn't return terminated string!
	 *       Output buffer from the fgetln can't be freed.
	 */

	// If the output buffer is not specified or is small, extend it.
	if (*lineptr == NULL || *n <= length) {
		char *tmp = realloc(*lineptr, length + 1);
		if (tmp == NULL) {
			return -1;
		}
		*lineptr = tmp;
		*n = length + 1;
	}

	memcpy(*lineptr, buffer, length);
	(*lineptr)[length] = '\0';

	return length;
#endif
#endif
}
