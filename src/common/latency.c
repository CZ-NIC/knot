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

#ifdef PROF_LATENCY

#include <sys/resource.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>


/*! \brief Profiler statistics. */
typedef struct pstat_t {
	double M;               /*!< \brief Mean value. */
	unsigned long min, max; /*!< \brief Minimum, maximum. */
	unsigned long total;    /*!< \brief Total profiled time. */
	unsigned long count;    /*!< \brief Number of profiled calls. */
} pstat_t;

/*! \brief Function call profile. */
typedef struct profile_t {
	const char* call;
	pstat_t stat;
} profile_t;

/*! \brief Observed function call codes. */
enum pcall_code_t {
	PF_RECVFROM = 0,
	PF_SENDTO,
	PF_PTHREAD_MUTEX_LOCK,
	PF_PTHREAD_MUTEX_UNLOCK,
	PF_CALL_SIZE
} pcall_code_t;

/*! \brief Table of observed function calls. */
static profile_t table[] = {
	{ "recvfrom",             {0} },
	{ "sendto",               {0} },
	{ "pthread_mutex_lock",   {0} },
	{ "pthread_mutex_unlock", {0} },
	{ "NULL",                 {0} }
};


/*! \brief Add value to statistics. */
static inline void add_stat(pstat_t *stat, unsigned long val) {

	if (val < stat->min) {
		stat->min = val;
	}
	if (val > stat->max) {
		stat->max = val;
	}

	stat->total += val;

	double Mprev = stat->M, M = stat->M;
	M += (val - M)/((double)stat->count + 1);
	stat->M = M;
	//S += (val - M)*(x[i] - Mprev);

	++stat->count;
}

/*! \brief Call profiler table initialization (automatically called on load). */
void __attribute__ ((constructor)) profiler_init()
{
	for (int i = 0; i < PF_CALL_SIZE; ++i) {
		pstat_t* stat = &table[i].stat;
		stat->M = 0;
		stat->max = 0;
		stat->min = (unsigned long)~0;
		stat->total = 0;
		stat->count = 0;
	}
}

/*! \brief Call profiler table evaluation (automatically called on exit). */
void __attribute__ ((destructor)) profiler_deinit()
{

	/* Get resource usage. */
	struct rusage usage;
	if (getrusage(RUSAGE_SELF, &usage) < 0) {
		memset(&usage, 0, sizeof(struct rusage));
	}

	fprintf(stderr, "\nStatistics:");
	fprintf(stderr, "\n==================\n");

	fprintf(stderr, "User time: %.03lf ms\nSystem time: %.03lf ms\n",
		usage.ru_utime.tv_sec * (double) 1000.0
		+ usage.ru_utime.tv_usec / (double)1000.0,
		usage.ru_stime.tv_sec * (double) 1000.0
		+ usage.ru_stime.tv_usec / (double)1000.0);
	fprintf(stderr, "Voluntary context switches: %lu\nInvoluntary context switches: %lu\n",
		usage.ru_nvcsw,
		usage.ru_nivcsw);
	fprintf(stderr, "==================\n");
	fprintf(stderr, "\n");

	/* Callers statistics. */
	for (int i = 0; i < PF_CALL_SIZE; ++i) {
		pstat_t* stat = &table[i].stat;
		fprintf(stderr, "%s: M=%lf min=%lu,max=%lu (total=%lu, %lu times) (usec)\n",
			table[i].call, stat->M, stat->min, stat->max, stat->total,
			stat->count);
	}

}

ssize_t pf_recvfrom(int socket, void *buf, size_t len, int flags,
		    struct sockaddr *from, socklen_t *fromlen,
		    const char* caller, const char* file, int line)
{
	unsigned long elapsed = 0;
	int ret = 0;
	perf_begin();
	ret = recvfrom(socket, buf, len, flags, from, fromlen);
	perf_end(elapsed);

	/* Discard wakeup delays, count statistics otherwise. */
	if (elapsed < 200000) {
		add_stat(&table[PF_RECVFROM].stat, elapsed);
	}
	return ret;
}

ssize_t pf_sendto(int socket, const void *buf, size_t len, int flags,
		  const struct sockaddr *to, socklen_t tolen,
		  const char* caller, const char* file, int line)
{
	unsigned long elapsed = 0;
	int ret = 0;
	perf_begin();
	ret = sendto(socket, buf, len, flags, to, tolen);
	perf_end(elapsed);

	/* Discard wakeup delays, count statistics otherwise. */
	if (elapsed < 200000) {
		add_stat(&table[PF_SENDTO].stat, elapsed);
	}
	return ret;
}

/* Pthreads */
int pf_pthread_mutex_lock(pthread_mutex_t *mutex,
			  const char* caller, const char* file, int line)
{
	unsigned long elapsed = 0;
	int ret = 0;
	perf_begin();
	ret = pthread_mutex_lock(mutex);
	perf_end(elapsed);

	/* Discard wakeup delays, count statistics otherwise. */
	if (elapsed < 200000) {
		add_stat(&table[PF_PTHREAD_MUTEX_LOCK].stat, elapsed);
	}

	return ret;
}

int pf_pthread_mutex_unlock(pthread_mutex_t *mutex,
			    const char* caller, const char* file, int line)
{
	unsigned long elapsed = 0;
	int ret = 0;
	perf_begin();
	ret = pthread_mutex_unlock(mutex);
	perf_end(elapsed);

	/* Discard wakeup delays, count statistics otherwise. */
	if (elapsed < 200000) {
		add_stat(&table[PF_PTHREAD_MUTEX_UNLOCK].stat, elapsed);
	}

	return ret;
}

#endif // PROF_LATENCY
