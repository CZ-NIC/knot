/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
