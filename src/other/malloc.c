#include "debug.h"

/*
 * Skip unit if not debugging memory.
 */
#ifdef MEM_DEBUG

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

struct pf_alloc_stat {
	const char *name;
	int count;
};

static int  __st_alloc_len;
static int *__st_alloc_size;
static int  __st_alloc_pflen;
static struct pf_alloc_stat *__st_alloc_pf;

static inline unsigned fastlog2(unsigned v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}

/* ((constructor)) attribute executes this function before main().
 * (255) means priority, higher number comes last.
 * (255) ensures it gets executed as last in constructor
 *       or as first in destructor.
 *       (Given that no other ((constructor)) requests priority > 255.)
 *
 * \see http://gcc.gnu.org/onlinedocs/gcc/Function-Attributes.html
 */
void __attribute__ ((constructor (255))) log_malloc_init()
{
	__st_alloc_len = sysconf(_SC_PAGESIZE);
	__st_alloc_pflen = 0;
	__st_alloc_size = malloc(__st_alloc_len * sizeof(int));
	__st_alloc_pf   = malloc(__st_alloc_len * sizeof(struct pf_alloc_stat));
	memset(__st_alloc_pf, 0, __st_alloc_len * sizeof(struct pf_alloc_stat));
	memset(__st_alloc_size, 0, __st_alloc_len * sizeof(int));
}

void __attribute__ ((destructor (255))) log_malloc_dump()
{
	/* Get resource usage. */
	struct rusage usage;
	if (getrusage(RUSAGE_SELF, &usage) < 0) {
		memset(&usage, 0, sizeof(struct rusage));
	}

	fprintf(stderr, "\nMemory statistics:");
	fprintf(stderr, "\n==================\n");
	unsigned long total = 0;
	unsigned long count = 0;
	double M=0, S=0;

	/* Algorithm by D.Knuth,
	   p. 232 of Vol 2 of The Art of Computer Programming, 1998 edition
	 */
	for (int i = 0; i < __st_alloc_len; ++i)
	{
		int val = __st_alloc_size[i];
		if(val > 0) {
			double Mprev = M;
			M += ((double)val - M)/((double)count + (double) 1.0);
			S += ((double)val - M)*((double)val - Mprev);
			total += val;
			++count;
		}
	}
	S = sqrt(S/(double)count);

	// Total, mean
	fprintf(stderr,   "Page size: %ld B\n", sysconf(_SC_PAGESIZE));
	fprintf(stderr,   "No. of callers: %d\n", __st_alloc_pflen);
	fprintf(stderr,   "Total malloc()'d: %lu times\n", total);
	//fprintf(stderr,   "Mean size: %.02Lf B\n", M);
	//fprintf(stderr,   "Standard deviation: %.02Lf\n", S);

	// Top 10 callers
	fprintf(stderr, "\nMost active callers:\n");
	fprintf(stderr, "==================\n");
	for (int i = 0; i < 10; ++i) {

		struct pf_alloc_stat *top = __st_alloc_pf;
		for (int j = 0; j < __st_alloc_pflen; ++j) {
			if (__st_alloc_pf[j].count > top->count) {
				top = __st_alloc_pf + j;
			}
		}

		if (top->name != 0) {
			fprintf(stderr, "%d times %s()\n", top->count, top->name);
			top->name  = 0;
			top->count = -1; // Invalidate
		}
	}


	// Dump results
	FILE* fp = fopen("malloc.dat", "w");
	fprintf(stderr, "\nAllocation counts:\n");
	fprintf(stderr, "==================\n");
	for (int i = 0; i < __st_alloc_len; ++i) {
		int times = __st_alloc_size[i];
		if (times > 0) {
			fprintf(stderr, "%4d B: %d times (%.02lf%%)\n",
			        i, times, times / (double) total * 100.0);
			for (int j = 0; j < times; ++j) {
				fprintf(fp, "%i\n", i);
			}
		}
	}
	fprintf(stderr, "\nCaches usage (log2 distribution):\n");
	fprintf(stderr, "==================\n");
	unsigned prev_boxid = log2f((unsigned) 0);
	double overhead = 0;
	int boxcount = 0;
	for (int i = 0; i < __st_alloc_len; ++i) {
		unsigned boxid = fastlog2((unsigned) i);
		if (boxid != prev_boxid) {
			if (boxcount > 0) {
				fprintf(stderr, "%4u B: %i times (%.02lf%%)\n",
				        prev_boxid, boxcount, boxcount / (double) total * 100.0);
			}
			boxcount = 0;
			prev_boxid = boxid;
		}

		boxcount += __st_alloc_size[i];
		overhead += __st_alloc_size[i] * (boxid - i);
	}
	const char* unit = "B";
	if (overhead > 2048.0)  {
		overhead = overhead / 1024;
		unit = "kB";
	}
	if (overhead > 2048.0) {
		overhead = overhead / 1024;
		unit = "MB";
	}

	fprintf(stderr, "\nSlots overhead: %.03lf %s\n", overhead, unit);
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
	fprintf(stderr, "Histogram data dumped to 'malloc.dat'\n");
	fclose(fp);
	free(__st_alloc_size);
	free(__st_alloc_pf);
}

void *log_malloc(const char *caller, int line, size_t size)
{
	static pthread_mutex_t st_lock = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_lock(&st_lock);
	if (size >= 0 && size < __st_alloc_len) {
		++__st_alloc_size[size];
	}

	struct pf_alloc_stat *stat = 0;
	for (int i = 0; i < __st_alloc_pflen; ++i) {
		if (strcmp(__st_alloc_pf[i].name, caller) == 0) {
			stat = __st_alloc_pf + i;
		}
	}
	if (stat == 0) {
		stat = __st_alloc_pf + __st_alloc_pflen;
		stat->name = caller;
		++__st_alloc_pflen;
	}
	++stat->count;
	pthread_mutex_unlock(&st_lock);

	/* fprintf(stderr, "malloc(): %s:%d allocated %u bytes\n",
	        caller, line, (unsigned) size);
	 */

	return malloc(size);
}
#endif

/*
#ifndef MEM_NOSLAB
#include "slab.h"
#include <stdlib.h>
#include <stdio.h>

static void *malloc(size_t size)
{
	void* mem = slab_alloc_g(size);
	fprintf(stderr, "malloc(%zu) = %p\n", size, mem);
	return mem;
}

static void free(void *ptr)
{
	slab_free(ptr);
}

static void *realloc(void *ptr, size_t size)
{
	return slab_realloc_g(ptr, size);
}
#endif
*/

