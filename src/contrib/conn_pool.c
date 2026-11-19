/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "contrib/conn_pool.h"

#include "contrib/openbsd/strlcpy.h"
#include "contrib/sockaddr.h"
#include "contrib/threads.h"

conn_pool_t *global_conn_pool = NULL;
conn_pool_t *global_sessticket_pool = NULL;
conn_pool_t *global_redis_pool = NULL;

const conn_pool_fd_t CONN_POOL_FD_INVALID = -1;

static conn_pool_fd_t pool_pop(conn_pool_t *pool, size_t i);

static bool expired(knot_time_t expiry, knot_time_t now)
{
	return expiry != 0 && now >= expiry;
}

/*!
 * \brief Try to get an open connection that is idle too long or whose lifetime expired.
 *
 * A connection qualifies if its last activity is older than \a older_than,
 * or if it has a non-zero expiry that is not later than \a now.
 *
 * \param pool           Pool to search in.
 * \param now            Current timestamp, used to evaluate connection expiry.
 * \param older_than     Timestamp that the connection's last activity must be older than.
 * \param next_oldest    Out: last-activity timestamp of the oldest remaining connection
 *                       (other than the returned), 0 if none.
 * \param next_expiry    Out: the earliest upcoming expiry among the remaining connections
 *                       (other than the returned) that have a lifetime set, 0 if none.
 *
 * \return -1 if error (no such connection), >= 0 connection file descriptor.
 *
 * \warning The returned connection is not necessarily the oldest or the earliest expired one.
 */
static conn_pool_fd_t get_old(conn_pool_t *pool,
                              knot_time_t now,
                              knot_time_t older_than,
                              knot_time_t *next_oldest,
                              knot_time_t *next_expiry)
{
	assert(pool);

	*next_oldest = 0;
	*next_expiry = 0;

	conn_pool_fd_t fd = CONN_POOL_FD_INVALID;
	pthread_mutex_lock(&pool->mutex);

	for (size_t i = 0; i < pool->capacity; i++) {
		knot_time_t la = pool->conns[i].last_active;
		knot_time_t ex = pool->conns[i].expiry;
		if (la == 0) {
			continue;
		}
		if (fd == CONN_POOL_FD_INVALID &&
		    (expired(ex, now) || knot_time_cmp(la, older_than) < 0)) {
			fd = pool_pop(pool, i);
			continue;
		}
		if (knot_time_cmp(la, *next_oldest) < 0) {
			*next_oldest = la;
		}
		if (ex != 0 && knot_time_cmp(ex, *next_expiry) < 0) {
			*next_expiry = ex;
		}
	}

	pthread_mutex_unlock(&pool->mutex);
	return fd;
}

static void *closing_thread(void *_arg)
{
	conn_pool_t *pool = _arg;

	while (true) {
		knot_time_t now = time_now().tv_sec, next = 0, next_exp = 0;
		knot_timediff_t timeout = conn_pool_timeout(pool, 0);
		assert(timeout != 0);

		int prev_state;
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prev_state);

		while (true) {
			conn_pool_fd_t old_fd = get_old(pool, now, now - timeout + 1,
			                                &next, &next_exp);
			if (old_fd != CONN_POOL_FD_INVALID) {
				pool->close_cb(old_fd);
			} else {
				break;
			}
		}

		pthread_setcancelstate(prev_state, NULL);

		now = time_now().tv_sec;
		knot_time_t wake = (next != 0) ? next + timeout : 0;
		wake = knot_time_min(wake, next_exp);
		if (wake != 0 && wake <= now) {
			continue; // something became due while closing
		}
		sleep((wake == 0) ? timeout : (unsigned)(wake - now));
	}

	return NULL;
}

conn_pool_t *conn_pool_init(size_t capacity, knot_timediff_t timeout,
                            conn_pool_close_cb_t close_cb,
                            conn_pool_invalid_cb_t invalid_cb)
{
	if (capacity == 0 || timeout <= 0) {
		return NULL;
	}

	conn_pool_t *pool = calloc(1, sizeof(*pool) + capacity * sizeof(pool->conns[0]));
	if (pool != NULL) {
		pool->capacity = capacity;
		pool->timeout = timeout;
		if (pthread_mutex_init(&pool->mutex, 0) != 0) {
			free(pool);
			return NULL;
		}
		if (thread_create_nosignal(&pool->closing_thread, closing_thread, pool) != 0) {
			pthread_mutex_destroy(&pool->mutex);
			free(pool);
			return NULL;
		}
		pool->close_cb = close_cb;
		pool->invalid_cb = invalid_cb;
	}
	return pool;
}

void conn_pool_purge(conn_pool_t *pool)
{
	if (pool != NULL) {
		conn_pool_fd_t fd;
		knot_time_t unused1, unused2;
		knot_time_t now = time_now().tv_sec;
		while ((fd = get_old(pool, now, 0, &unused1, &unused2)) != CONN_POOL_FD_INVALID) {
			pool->close_cb(fd);
		}
	}
}

void conn_pool_deinit(conn_pool_t *pool)
{
	if (pool != NULL) {
		pthread_cancel(pool->closing_thread);
		pthread_join(pool->closing_thread, NULL);
		conn_pool_purge(pool);
		pthread_mutex_destroy(&pool->mutex);
		free(pool);
	}
}

knot_timediff_t conn_pool_timeout(conn_pool_t *pool,
                                  knot_timediff_t new_timeout)
{
	if (pool == NULL) {
		return 0;
	}

	pthread_mutex_lock(&pool->mutex);

	knot_timediff_t prev = pool->timeout;
	if (new_timeout > 0) {
		pool->timeout = new_timeout;
	}

	pthread_mutex_unlock(&pool->mutex);
	return prev;
}

static conn_pool_fd_t pool_pop(conn_pool_t *pool, size_t i)
{
	conn_pool_memb_t *conn = &pool->conns[i];
	assert(conn->last_active != 0);
	assert(pool->usage > 0);
	conn_pool_fd_t fd = conn->fd;
	memset(conn, 0, sizeof(*conn));
	pool->usage--;
	return fd;
}

conn_pool_fd_t conn_pool_get(conn_pool_t *pool,
                             const struct sockaddr_storage *src,
                             const struct sockaddr_storage *dst,
                             const char *dev)
{
	if (pool == NULL) {
		return CONN_POOL_FD_INVALID;
	}

	const char *dev_str = (dev != NULL) ? dev : "";
	knot_time_t now = time_now().tv_sec;

	while (true) {
		conn_pool_fd_t fd = CONN_POOL_FD_INVALID;
		knot_time_t ex = 0;

		pthread_mutex_lock(&pool->mutex);
		for (size_t i = 0; i < pool->capacity; i++) {
			if (pool->conns[i].last_active != 0 &&
			    sockaddr_cmp(&pool->conns[i].dst, dst, false) == 0 &&
			    sockaddr_cmp(&pool->conns[i].src, src, true) == 0 &&
			    strcmp(pool->conns[i].dev, dev_str) == 0) {
				ex = pool->conns[i].expiry;
				fd = pool_pop(pool, i);
				break;
			}
		}
		pthread_mutex_unlock(&pool->mutex);

		if (fd == CONN_POOL_FD_INVALID) {
			return CONN_POOL_FD_INVALID; // no (more) matching connections
		}

		if (expired(ex, now) || (pool->invalid_cb != NULL && pool->invalid_cb(fd))) {
			pool->close_cb(fd);
			continue; // expired or stale, try the next matching one
		}

		return fd;
	}
}

static void pool_push(conn_pool_t *pool, size_t i,
                      const struct sockaddr_storage *src,
                      const struct sockaddr_storage *dst,
                      const char *dev,
                      uint32_t lftime,
                      conn_pool_fd_t fd)
{
	conn_pool_memb_t *conn = &pool->conns[i];
	assert(conn->last_active == 0);
	assert(pool->usage < pool->capacity);
	conn->last_active = time_now().tv_sec;
	conn->expiry = (lftime > 0) ? conn->last_active + lftime - 1 : 0; // 1-second margin
	conn->fd = fd;
	memcpy(&conn->src, src, sizeof(conn->src));
	memcpy(&conn->dst, dst, sizeof(conn->dst));
	strlcpy(conn->dev, (dev != NULL) ? dev : "", sizeof(conn->dev));
	pool->usage++;
}

conn_pool_fd_t conn_pool_put(conn_pool_t *pool,
                             const struct sockaddr_storage *src,
                             const struct sockaddr_storage *dst,
                             const char *dev,
                             uint32_t lftime,
                             conn_pool_fd_t fd)
{
	if (pool == NULL || pool->capacity == 0) {
		return fd;
	}

	knot_time_t now = time_now().tv_sec;
	knot_time_t oldest_time = 0;
	size_t oldest_i = pool->capacity;
	size_t expired_i = pool->capacity;

	pthread_mutex_lock(&pool->mutex);

	for (size_t i = 0; i < pool->capacity; i++) {
		knot_time_t la = pool->conns[i].last_active;
		if (la == 0) {
			// Free slot, nothing needs to be evicted.
			pool_push(pool, i, src, dst, dev, lftime, fd);
			pthread_mutex_unlock(&pool->mutex);
			return CONN_POOL_FD_INVALID;
		}

		knot_time_t ex = pool->conns[i].expiry;
		if (expired_i == pool->capacity && expired(ex, now)) {
			expired_i = i;
		}

		if (knot_time_cmp(la, oldest_time) < 0) {
			oldest_time = la;
			oldest_i = i;
		}
	}

	// Pool is full: prefer an expired entry, otherwise the least recently used.
	size_t victim = (expired_i < pool->capacity) ? expired_i : oldest_i;
	assert(victim < pool->capacity);

	conn_pool_fd_t victim_fd = pool_pop(pool, victim);
	pool_push(pool, victim, src, dst, dev, lftime, fd);
	pthread_mutex_unlock(&pool->mutex);
	return victim_fd;
}

void conn_pool_close_cb_dflt(conn_pool_fd_t fd)
{
	if (fd != CONN_POOL_FD_INVALID) {
		close((int)fd);
	}
}

bool conn_pool_invalid_cb_dflt(conn_pool_fd_t fd)
{
	uint8_t unused;
	errno = 0;
	int peek = recv((int)fd, &unused, 1, MSG_PEEK | MSG_DONTWAIT);
	return (peek == 0 || peek > 0 || errno == ECONNRESET); // closed || pending data || reset (alternative: errno != 0 && errno != EAGAIN)
}
