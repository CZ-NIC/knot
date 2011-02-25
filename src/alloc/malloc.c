#include <config.h>
/*
 * Skip unit if not debugging memory.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

#include "common.h"
#include "other/debug.h"

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
