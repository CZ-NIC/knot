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
/*!
 * \file latency.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Utilities for latency profiling.
 *
 * Selected calls latency profiler is enabled with PROF_LATENCY define.
 * You can roughly profile own code with perf_begin() and perf_end() macros.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_COMMON_LATENCY_H_
#define _KNOTD_COMMON_LATENCY_H_

/* Optional. */
#ifdef PROF_LATENCY

/* Do not include from latency.c */
#include <sys/time.h>
#include <sys/socket.h>
#include <pthread.h>

/* Profiler tools */

/*! \brief Time profile begin macro. */
#define perf_begin() \
do { \
	struct timeval __begin; \
	gettimeofday(&__begin, 0)

/*! \brief Time profile end macro
 *  \param d Will contain the number of microseconds passed from perf_begin().
 */
#define perf_end(d) \
	struct timeval __end; \
	gettimeofday(&__end, 0); \
	unsigned long __us = (__end.tv_sec - __begin.tv_sec) * 1000L * 1000L; \
	__us += (__end.tv_usec - __begin.tv_usec); \
	(d) = __us; \
} while(0)

/* Prototypes. */

/*! \brief Profiled recvfrom(). */
ssize_t pf_recvfrom(int socket, void *buf, size_t len, int flags,
		    struct sockaddr *from, socklen_t *fromlen,
		    const char* caller, const char* file, int line);

/*! \brief Profiled sendto(). */
ssize_t pf_sendto(int socket, const void *buf, size_t len, int flags,
		  const struct sockaddr *to, socklen_t tolen,
		  const char* caller, const char* file, int line);

/*! \brief Profiled pthread_mutex_lock(). */
int pf_pthread_mutex_lock(pthread_mutex_t *mutex,
			  const char* caller, const char* file, int line);

/*! \brief Profiled pthread_mutex_unlock(). */
int pf_pthread_mutex_unlock(pthread_mutex_t *mutex,
			    const char* caller, const char* file, int line);

/*
 * Sockets.
 */

/*! \brief Rerouted recvfrom(). */
#define recvfrom(s, buf, len, flags, from, fromlen) \
	pf_recvfrom((s), (buf), (len), (flags), (from), (fromlen), \
		    __FUNCTION__, __FILE__, __LINE__)

/*! \brief Rerouted sendto(). */
#define sendto(s, buf, len, flags, to, tolen) \
	pf_sendto((s), (buf), (len), (flags), (to), (tolen), \
		  __FUNCTION__, __FILE__, __LINE__)

/*
 * Pthreads.
 */

/*! \brief Rerouted pthread_mutex_lock(). */
#define pthread_mutex_lock(m) \
	pf_pthread_mutex_lock(m, __FUNCTION__, __FILE__, __LINE__)

/*! \brief Rerouted pthread_mutex_unlock(). */
#define pthread_mutex_unlock(m) \
	pf_pthread_mutex_unlock(m, __FUNCTION__, __FILE__, __LINE__)

#else // PROF_LATENCY

/* Profiler tools */
#define perf_begin()
#define perf_end(d)

#endif // PROF_LATENCY
#endif // _KNOTD_COMMON_LATENCY_H_

/*! @} */
