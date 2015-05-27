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

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include "libknot/internal/macros.h"
#include "libknot/internal/mem.h"

uint8_t *knot_memdup(const uint8_t *data, size_t data_size)
{
	uint8_t *result = (uint8_t *)malloc(data_size);
	if (!result) {
		return NULL;
	}

	return memcpy(result, data, data_size);
}

void* xmalloc(size_t l)
{
	void *p = malloc(l);
	if (p == NULL) {
		abort();
	}
	return p;
}

void *xrealloc(void *p, size_t l)
{
	p = realloc(p, l);
	if (p == NULL) {
		abort();
	}
	return p;
}

int mreserve(char **p, size_t tlen, size_t min, size_t allow, size_t *reserved)
{
	/* Trim excessive memory if possible. */
	size_t maxlen = min + allow;
	if (maxlen < min) {
		return -2; /* size_t overflow */
	}

	/* Meet target size but trim excessive amounts. */
	if (*reserved < min || *reserved > maxlen) {
		void *trimmed = realloc(*p, maxlen * tlen);
		if (trimmed != NULL) {
			*p = trimmed;
			*reserved = maxlen;
		} else {
			return -1;
		}
	}

	return 0;
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

#ifdef MEM_DEBUG
/*
 * ((destructor)) attribute executes this function after main().
 * \see http://gcc.gnu.org/onlinedocs/gcc/Function-Attributes.html
 */
void __attribute__ ((destructor)) usage_dump()
#else
void usage_dump()
#endif
{
	/* Get resource usage. */
	struct rusage usage;
	if (getrusage(RUSAGE_SELF, &usage) < 0) {
		memset(&usage, 0, sizeof(struct rusage));
	}

	fprintf(stderr, "\nMemory statistics:");
	fprintf(stderr, "\n==================\n");

	fprintf(stderr, "User time: %.03lf ms\nSystem time: %.03lf ms\n",
	        usage.ru_utime.tv_sec * (double) 1000.0
	        + usage.ru_utime.tv_usec / (double)1000.0,
	        usage.ru_stime.tv_sec * (double) 1000.0
	        + usage.ru_stime.tv_usec / (double)1000.0);
	fprintf(stderr, "Major page faults: %lu (required I/O)\nMinor page faults: %lu\n",
	        usage.ru_majflt, usage.ru_minflt);
	fprintf(stderr, "Number of swaps: %lu\n",
	        usage.ru_nswap);
	fprintf(stderr, "Voluntary context switches: %lu\nInvoluntary context switches: %lu\n",
	        usage.ru_nvcsw,
	        usage.ru_nivcsw);
	fprintf(stderr, "==================\n");
}
