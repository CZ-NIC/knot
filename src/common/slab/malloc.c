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
/*
 * Skip unit if not debugging memory.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

#include "common/slab/alloc-common.h"

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
