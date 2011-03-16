#ifndef _LATENCYPROF_H_
#define _LATENCYPROF_H_

/* Optional. */
#ifdef PROF_LATENCY

/* Do not include from latency.c */
#include <sys/socket.h>
#include <pthread.h>

/* Prototypes. */
ssize_t pf_recvfrom(int socket, void *buf, size_t len, int flags,
		    struct sockaddr *from, socklen_t *fromlen,
		    const char* caller, const char* file, int line);

ssize_t pf_sendto(int socket, const void *buf, size_t len, int flags,
		  const struct sockaddr *to, socklen_t tolen,
		  const char* caller, const char* file, int line);

int pf_pthread_mutex_lock(pthread_mutex_t *mutex,
			  const char* caller, const char* file, int line);

int pf_pthread_mutex_unlock(pthread_mutex_t *mutex,
			    const char* caller, const char* file, int line);

/* Sockets. */
#define recvfrom(s, buf, len, flags, from, fromlen) \
	pf_recvfrom((s), (buf), (len), (flags), (from), (fromlen), \
		    __FUNCTION__, __FILE__, __LINE__)

#define sendto(s, buf, len, flags, to, tolen) \
	pf_sendto((s), (buf), (len), (flags), (to), (tolen), \
		  __FUNCTION__, __FILE__, __LINE__)

/* Pthreads. */
#define pthread_mutex_lock(m) \
	pf_pthread_mutex_lock(m, __FUNCTION__, __FILE__, __LINE__)

#define pthread_mutex_unlock(m) \
	pf_pthread_mutex_unlock(m, __FUNCTION__, __FILE__, __LINE__)

#endif // PROF_LATENCY
#endif // _LATENCYPROF_H_
