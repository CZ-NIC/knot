#ifndef __CUTEDNS_MALLOC_H__
#define __CUTEDNS_MALLOC_H__

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <math.h>
#include <unistd.h>

struct pf_alloc_stat {
    const char *name;
    int count;
};

int  __st_alloc_len;
int *__st_alloc_size;
int  __st_alloc_pflen;
struct pf_alloc_stat *__st_alloc_pf;

static inline void log_malloc_dump()
{
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
            M += ((double)val - M)/((double)count + 1.0);
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
    fprintf(stderr,   "Mean size: %.02lf B\n", M);
    fprintf(stderr,   "Standard deviation: %.02lf\n", S);

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
    fprintf(stderr, "==================\n");
    fprintf(stderr, "Histogram data dumped to 'malloc.dat'\n");
    fclose(fp);
    free(__st_alloc_size);
    free(__st_alloc_pf);
}

static inline void log_malloc_init()
{
    __st_alloc_len = 4096;
    __st_alloc_pflen = 0;
    __st_alloc_size = malloc(__st_alloc_len * sizeof(int));
    __st_alloc_pf   = malloc(__st_alloc_len * sizeof(struct pf_alloc_stat));
    memset(__st_alloc_pf, 0, __st_alloc_len * sizeof(struct pf_alloc_stat));
    memset(__st_alloc_size, 0, __st_alloc_len * sizeof(int));
}

static inline void *log_malloc(const char *caller, int line, size_t size)
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

    /*fprintf(stderr, "malloc(): %s:%d allocated %u bytes\n",
            caller, line, (unsigned) size); */

    return malloc(size);
}

#define malloc(x) log_malloc(__func__, __LINE__, (x))

#endif
